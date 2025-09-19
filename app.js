/* PassVault (fresh build) */
(function(){
  const $ = (sel, root=document) => root.querySelector(sel);

  // Elements (set after DOMContentLoaded)
  let scrOnboarding, scrLock, scrApp, msgOnboarding, msgLock, panel;

  // IndexedDB (robust open + auto-repair if store missing)
  const DB_NAME="passvault-db", DB_STORE="kv", DB_VERSION=3;
  function openDB(){
    return new Promise((resolve,reject)=>{
      try{
        const req=indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded=()=>{
          const db=req.result;
          if(!db.objectStoreNames.contains(DB_STORE)) db.createObjectStore(DB_STORE);
        };
        req.onsuccess=()=>{
          const db=req.result;
          if(!db.objectStoreNames.contains(DB_STORE)){
            const newVersion=(db.version||DB_VERSION)+1;
            db.close();
            const req2=indexedDB.open(DB_NAME, newVersion);
            req2.onupgradeneeded=()=>{
              const db2=req2.result;
              if(!db2.objectStoreNames.contains(DB_STORE)) db2.createObjectStore(DB_STORE);
            };
            req2.onsuccess=()=>resolve(req2.result);
            req2.onerror=()=>reject(req2.error);
          } else { resolve(db); }
        };
        req.onerror=()=>reject(req.error);
      }catch(e){ reject(e); }
    });
  }
  async function dbGet(key){ const db=await openDB(); return new Promise((res,rej)=>{ try{ const tx=db.transaction(DB_STORE,"readonly"); const st=tx.objectStore(DB_STORE); const r=st.get(key); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error);}catch(err){ rej(err);} }); }
  async function dbSet(key,value){ const db=await openDB(); return new Promise((res,rej)=>{ try{ const tx=db.transaction(DB_STORE,"readwrite"); const st=tx.objectStore(DB_STORE); const r=st.put(value,key); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error);}catch(err){ rej(err);} }); }
  async function dbDel(key){ const db=await openDB(); return new Promise((res,rej)=>{ try{ const tx=db.transaction(DB_STORE,"readwrite"); const st=tx.objectStore(DB_STORE); const r=st.delete(key); r.onsuccess=()=>res(); r.onerror=()=>rej(r.error);}catch(err){ rej(err);} }); }

  // Crypto helpers
  const enc=new TextEncoder(), dec=new TextDecoder();
  function b64url(bytes){ return btoa(String.fromCharCode(...bytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""); }
  function fromB64url(str){ str=str.replace(/-/g,"+").replace(/_/g,"/"); const pad=str.length%4?4-(str.length%4):0; str+="=".repeat(pad); const bin=atob(str); return new Uint8Array([...bin].map(c=>c.charCodeAt(0))); }
  async function randomBytes(len=32){ const b=new Uint8Array(len); crypto.getRandomValues(b); return b; }
  async function pbkdf2Key(pin, salt, iterations=150000){
    const keyMat=await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({name:"PBKDF2", hash:"SHA-256", salt, iterations}, keyMat, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
  }
  async function aesEncrypt(key, data){ const iv=await randomBytes(12); const pt=typeof data==="string"?enc.encode(data):data; const ct=await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, pt); return { iv:b64url(iv), ct:b64url(new Uint8Array(ct)) }; }
  async function aesDecrypt(key, ivB64, ctB64){ const iv=fromB64url(ivB64), ct=fromB64url(ctB64); const pt=await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, ct); return new Uint8Array(pt); }
  async function exportRawKey(key){ const jwk=await crypto.subtle.exportKey("jwk", key); return jwk.k; }
  async function importAesKeyFromJwkK(k){ return crypto.subtle.importKey("jwk", {kty:"oct", k:k, alg:"A256GCM", ext:true}, {name:"AES-GCM"}, false, ["encrypt","decrypt"]); }

  // App state
  const state={ unlocked:false, masterKey:null, vault:[], requireBio:false, credId:null };

  // Storage helpers
  const getMeta=()=>dbGet("meta");
  const setMeta=(m)=>dbSet("meta", m);
  const getWrappedKey=()=>dbGet("wrappedKey");
  const setWrappedKey=(o)=>dbSet("wrappedKey", o);
  async function saveVault(){ if(!state.masterKey) throw new Error("Vault not unlocked"); const payload=JSON.stringify({ entries: state.vault }); const {iv, ct}=await aesEncrypt(state.masterKey, payload); await dbSet("vault", { iv, ct, v:1 }); }
  async function loadVault(){ const blob=await dbGet("vault"); if(!blob){ state.vault=[]; return; } const pt=await aesDecrypt(state.masterKey, blob.iv, blob.ct); const obj=JSON.parse(dec.decode(pt)); state.vault=obj.entries||[]; }

  // WebAuthn (Chrome)
  function isWebAuthnAvailable(){ return !!(window.PublicKeyCredential && navigator.credentials); }
  async function createPlatformCredential(){
    const challenge=crypto.getRandomValues(new Uint8Array(32));
    const userId=crypto.getRandomValues(new Uint8Array(16));
    const pubKey={
      challenge,
      rp:{ name:"PassVault", id: location.hostname },
      user:{ id:userId, name:"passvault-user", displayName:"PassVault User" },
      pubKeyCredParams:[{type:"public-key", alg:-7},{type:"public-key", alg:-257}],
      timeout:60000,
      authenticatorSelection:{ authenticatorAttachment:"platform", userVerification:"required" },
      attestation:"none"
    };
    const cred=await navigator.credentials.create({ publicKey: pubKey });
    return b64url(new Uint8Array(cred.rawId));
  }
  async function requestUserVerification(credIdB64url){
    const challenge=crypto.getRandomValues(new Uint8Array(32));
    const allowCreds=credIdB64url?[{type:"public-key", id:fromB64url(credIdB64url), transports:["internal"]}]:[];
    await navigator.credentials.get({ publicKey:{ challenge, timeout:60000, userVerification:"required", allowCredentials:allowCreds } });
    return true;
  }

  // UI helpers
  function showOnboarding(){ scrOnboarding.classList.remove("hidden"); scrLock.classList.add("hidden"); scrApp.classList.add("hidden"); }
  function showLock(){ scrOnboarding.classList.add("hidden"); scrLock.classList.remove("hidden"); scrApp.classList.add("hidden"); }
  function showApp(){ scrOnboarding.classList.add("hidden"); scrLock.classList.add("hidden"); scrApp.classList.remove("hidden"); renderList($("#search").value); }
  function openPanel(){ panel.classList.add("show"); }
  function closePanel(){ panel.classList.remove("show"); }

  // Actions
  // === SD card / Folder backup ===
  let backupDir = null;

  async function verifyPermission(handle, write=false) {
    if (!handle) return false;
    const opts = { mode: write ? 'readwrite' : 'read' };
    if ((await handle.queryPermission?.(opts)) === 'granted') return true;
    if ((await handle.requestPermission?.(opts)) === 'granted') return true;
    return false;
  }

  async function chooseBackupFolder(){
    if (!('showDirectoryPicker' in window)) {
      alert('Your browser does not support choosing a folder. Use Export Encrypted Backup instead.');
      return;
    }
    try{
      const dir = await window.showDirectoryPicker({ id: 'passvault-backups' });
      // Request write permission
      const ok = await verifyPermission(dir, true);
      if (!ok) { alert('Permission denied for this folder.'); return; }
      backupDir = dir;
      await dbSet('backupDir', dir); // store handle (structured clone)
      alert('Backup folder set. Use "Save Backup to Folder" to write .vault files here.');
    }catch(e){
      if (e?.name !== 'AbortError') alert('Folder selection failed: ' + e.message);
    }
  }

  async function exportBackupToFolder(){
    try{
      // Ensure vault is unlocked
      if (!state.unlocked) { alert('Unlock first.'); return; }
      // Ensure we have a directory handle
      if (!backupDir) {
        const fromDB = await dbGet('backupDir');
        if (fromDB) backupDir = fromDB;
      }
      if (!backupDir) {
        await chooseBackupFolder();
        if (!backupDir) return;
      }
      // Check permission again
      if (!(await verifyPermission(backupDir, true))) {
        alert('No permission to write to this folder.');
        return;
      }
      // Build encrypted payload (same as exportBackup)
      const pass = prompt('Set a backup password (store it safely):');
      if (!pass) return;
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const key = await pbkdf2Key(pass, salt, 200000);
      const payload = JSON.stringify({ meta: await getMeta(), data: state.vault });
      const { iv, ct } = await aesEncrypt(key, payload);
      const fileName = `passvault-backup-${new Date().toISOString().slice(0,10)}.vault`;
      const fileHandle = await backupDir.getFileHandle(fileName, { create: true });
      const writable = await fileHandle.createWritable();
      await writable.write(JSON.stringify({ v:1, salt: b64url(salt), iv, ct }));
      await writable.close();
      alert('Backup saved to folder: ' + fileName + '\nTip: Choose your SD card folder in the picker to save there.');
    }catch(e){
      console.error(e);
      alert('Save to folder failed: ' + e.message + '\nFalling back to download.');
      await exportBackup(); // fallback
    }
  }

  async function handleSetup(){
    msgOnboarding.textContent="";
    const pin=$("#setup-pin").value.trim();
    const enableBio=$("#setup-bio").checked;
    if(pin.length<4){ msgOnboarding.textContent="PIN must be at least 4 characters."; return; }
    try{
      const mk=await crypto.subtle.generateKey({name:"AES-GCM", length:256}, true, ["encrypt","decrypt"]);
      const mkJwkK=await exportRawKey(mk);
      const salt=await randomBytes(16);
      const wrapKey=await pbkdf2Key(pin, salt);
      const encMK=await aesEncrypt(wrapKey, new TextEncoder().encode(mkJwkK));
      let credId=null;
      if(enableBio){
        if(!window.isSecureContext){ alert("Biometrics require HTTPS (or localhost). You can still use PIN."); }
        else if(isWebAuthnAvailable()){
          try{ credId=await createPlatformCredential(); }catch(e){ alert("Biometric setup failed on this device. You can continue with PIN."); }
        } else { alert("Biometrics not supported on this browser/device."); }
      }
      await setWrappedKey({ salt:b64url(salt), iv:encMK.iv, ct:encMK.ct, algo:"AES-GCM", pbkdf2:{iter:150000, hash:"SHA-256"} });
      await setMeta({ requireBio: !!credId, credId, createdAt: Date.now(), v:1 });
      state.masterKey=mk; state.unlocked=true; state.requireBio=!!credId; state.credId=credId;
      await saveVault(); await loadVault(); showApp();
    }catch(e){ msgOnboarding.textContent="Setup failed: "+e.message; }
  }

  async function handleUnlock(){
    msgLock.textContent="";
    const pin=$("#unlock-pin").value.trim();
    if(!pin){ msgLock.textContent="Enter your PIN."; return; }
    try{
      const meta=await getMeta(); if(!meta) throw new Error("Not set up yet.");
      if(meta.requireBio){
        try{ await requestUserVerification(meta.credId); }
        catch{ msgLock.textContent="Biometric verification failed or cancelled."; return; }
      }
      const wrap=await getWrappedKey();
      const salt=fromB64url(wrap.salt);
      const wrapKey=await pbkdf2Key(pin, salt, wrap.pbkdf2?.iter||150000);
      const mkJwkKBytes=await aesDecrypt(wrapKey, wrap.iv, wrap.ct);
      const mkJwkK=new TextDecoder().decode(mkJwkKBytes);
      const mk=await importAesKeyFromJwkK(mkJwkK);
      state.masterKey=mk; state.unlocked=true; state.requireBio=!!meta.requireBio; state.credId=meta.credId||null;
      await loadVault(); showApp();
    }catch(e){ msgLock.textContent="Unlock failed. Check your PIN."; }
  }

  function doLock(){ state.unlocked=false; state.masterKey=null; state.vault=[]; $("#unlock-pin").value=""; showLock(); }

  function uid(){ return crypto.randomUUID(); }
  function nowISO(){ return new Date().toISOString(); }
  function renderList(filter=""){
    const list=$("#list"); list.innerHTML="";
    const q=(filter||"").toLowerCase();
    const entries=state.vault
      .filter(e=>!q || e.app.toLowerCase().includes(q) || e.username.toLowerCase().includes(q))
      .sort((a,b)=>(b.updatedAt||b.createdAt||"").localeCompare(a.updatedAt||a.createdAt||""));
    for(const e of entries){
      const card=document.createElement("div");
      card.className="p-3 border rounded-2xl flex gap-3 items-start";
      card.innerHTML=`
        <div class="grow">
          <div class="font-medium">${e.app}</div>
          <div class="text-xs text-slate-500 break-all">${e.url||""}</div>
          <div class="mt-1 text-sm"><span class="text-slate-500">User:</span> ${e.username}</div>
          <div class="mt-1 flex gap-2">
            <button class="btn bg-slate-100" data-act="copy-user" data-id="${e.id}">Copy user</button>
            <button class="btn bg-slate-100" data-act="copy-pass" data-id="${e.id}">Copy pass</button>
            <button class="btn bg-slate-100" data-act="open" data-id="${e.id}">Open</button>
            <button class="btn bg-sky-600 text-white" data-act="edit" data-id="${e.id}">Edit</button>
            <button class="btn bg-rose-600 text-white" data-act="del" data-id="${e.id}">Delete</button>
          </div>
        </div>`;
      list.appendChild(card);
    }
  }

  async function copyToClipboard(text){ try{ await navigator.clipboard.writeText(text); }catch{ alert("Clipboard blocked by browser permissions."); } }
  function openEntry(id){
    const item=state.vault.find(x=>x.id===id); if(!item) return;
    $("#dlg-title").textContent="Edit Entry";
    $("#f-id").value=item.id; $("#f-app").value=item.app; $("#f-url").value=item.url||""; $("#f-username").value=item.username; $("#f-password").value=item.password;
    openPanel();
  }
  function newEntry(){
    $("#dlg-title").textContent="Add Entry";
    $("#f-id").value=""; $("#f-app").value=""; $("#f-url").value=""; $("#f-username").value=""; $("#f-password").value="";
    openPanel();
  }
  async function saveEntry(){
    const id=$("#f-id").value || uid();
    const entry={ id, app:$("#f-app").value.trim(), url:$("#f-url").value.trim(), username:$("#f-username").value.trim(), password:$("#f-password").value, createdAt: $("#f-id").value ? undefined : nowISO(), updatedAt: nowISO() };
    if(!entry.app || !entry.username){ alert("App/Site and Username are required."); return; }
    const idx=state.vault.findIndex(x=>x.id===id);
    if(idx>=0) state.vault[idx]={ ...state.vault[idx], ...entry }; else state.vault.push(entry);
    await saveVault(); closePanel(); renderList($("#search").value);
  }
  async function deleteEntry(id){
    if(!confirm("Delete this entry?")) return;
    const idx=state.vault.findIndex(x=>x.id===id); if(idx>=0){ state.vault.splice(idx,1); await saveVault(); renderList($("#search").value); }
  }

  function randInt(max){ return crypto.getRandomValues(new Uint32Array(1))[0] % max; }
  function pick(chars){ return chars[randInt(chars.length)]; }
  function generatePassword(opts){
    const lower="abcdefghijklmnopqrstuvwxyz", upper="ABCDEFGHIJKLMNOPQRSTUVWXYZ", nums="0123456789", syms="!@#$%^&*()_-+=[]{};:,.?/|`~";
    let pool="", must=[];
    if(opts.lower){ pool+=lower; must.push(pick(lower)); }
    if(opts.upper){ pool+=upper; must.push(pick(upper)); }
    if(opts.num){ pool+=nums; must.push(pick(nums)); }
    if(opts.sym){ pool+=syms; must.push(pick(syms)); }
    if(!pool) pool=lower+upper+nums;
    const len=Math.max(8, Math.min(64, opts.length||20));
    let out=must.join(""); while(out.length<len) out+=pick(pool);
    const a=out.split(""); for(let i=a.length-1;i>0;i--){ const j=randInt(i+1); [a[i],a[j]]=[a[j],a[i]]; } return a.join("");
  }

  async function exportBackup(){
    if(!state.unlocked) return alert("Unlock first.");
    const pass=prompt("Set a backup password (store it safely):"); if(!pass) return;
    const salt=crypto.getRandomValues(new Uint8Array(16));
    const key=await pbkdf2Key(pass, salt, 200000);
    const payload=JSON.stringify({ meta: await getMeta(), data: state.vault });
    const {iv, ct}=await aesEncrypt(key, payload);
    const blob=new Blob([JSON.stringify({ v:1, salt:b64url(salt), iv, ct })], {type:"application/json"});
    const url=URL.createObjectURL(blob); const a=document.createElement("a");
    a.href=url; a.download=`passvault-backup-${new Date().toISOString().slice(0,10)}.vault`; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  }

  async function importBackupFile(file){
    try{
      const obj=JSON.parse(await file.text());
      if(!obj||!obj.salt||!obj.iv||!obj.ct) throw new Error("Invalid file");
      const pass=prompt("Enter backup password:"); if(!pass) return;
      const key=await pbkdf2Key(pass, fromB64url(obj.salt), 200000);
      const pt=await aesDecrypt(key, obj.iv, obj.ct);
      const payload=JSON.parse(new TextDecoder().decode(pt));
      // Import disables biometrics (credential is device-bound); user can re-enable
      await setMeta({ ...(payload.meta||{}), requireBio:false, credId:null });
      state.requireBio=false; state.credId=null;
      state.vault=payload.data||[]; await saveVault();
      alert("Import complete. Biometrics disabled after restore; set up again if desired.");
      renderList($("#search").value);
    }catch(e){ alert("Import failed: "+e.message); }
  }

  async function decideScreen(){ const meta=await getMeta(); if(!meta) showOnboarding(); else showLock(); }

  // Bind after DOM ready
  window.addEventListener("DOMContentLoaded", ()=>{
    // PWA install flow
    let deferredPrompt = null;
    const installBtn = document.querySelector("#btn-install");
    function showInstall(){ if(installBtn) installBtn.classList.remove("hidden"); }
    function hideInstall(){ if(installBtn) installBtn.classList.add("hidden"); }
    window.addEventListener("beforeinstallprompt", (e)=>{ e.preventDefault(); deferredPrompt = e; showInstall(); });
    window.addEventListener("appinstalled", ()=>{ deferredPrompt = null; hideInstall(); });
    if (window.matchMedia && window.matchMedia("(display-mode: standalone)").matches) hideInstall();
    if (installBtn) installBtn.addEventListener("click", async ()=>{
      if(!deferredPrompt) return;
      deferredPrompt.prompt();
      const { outcome } = await deferredPrompt.userChoice;
      deferredPrompt = null;
      if(outcome !== "accepted") showInstall(); else hideInstall();
    });

    scrOnboarding=$("#screen-onboarding"); scrLock=$("#screen-lock"); scrApp=$("#screen-app");
    msgOnboarding=$("#onboarding-msg"); msgLock=$("#lock-msg"); panel=$("#panel");

    $("#btn-setup")?.addEventListener("click", handleSetup);
    $("#btn-import-first")?.addEventListener("click", ()=>$("#file-import").click());
    $("#btn-unlock")?.addEventListener("click", handleUnlock);
    $("#btn-bio")?.addEventListener("click", async ()=>{
      try{
        const meta=await getMeta();
        if(!meta?.credId){ alert("Biometrics not enabled. Reset vault to enable it, or keep using PIN."); return; }
        await requestUserVerification(meta.credId);
        alert("Biometric check passed. Now enter PIN to decrypt.");
      }catch{ alert("Biometric failed or cancelled."); }
    });
    $("#btn-lock")?.addEventListener("click", doLock);
    $("#btn-add")?.addEventListener("click", newEntry);
    $("#save")?.addEventListener("click", (e)=>{ e.preventDefault?.(); saveEntry(); });
    $("#cancel")?.addEventListener("click", (e)=>{ e.preventDefault?.(); closePanel(); });
    $("#close-panel")?.addEventListener("click", ()=>closePanel());
    $("#gen")?.addEventListener("click", ()=>{
      const opts={ lower:$("#g-lower").checked, upper:$("#g-upper").checked, num:$("#g-num").checked, sym:$("#g-sym").checked, length:parseInt($("#g-len").value,10)||20 };
      $("#f-password").value=generatePassword(opts);
    });
    $("#g-len")?.addEventListener("input", ()=> $("#g-len-val").textContent=$("#g-len").value );
    $("#search")?.addEventListener("input", (e)=>renderList(e.target.value));
    $("#file-import")?.addEventListener("change", async (e)=>{ const f=e.target.files?.[0]; if(f) await importBackupFile(f); e.target.value=""; });
    $("#btn-export")?.addEventListener("click", exportBackup);
    $("#btn-choose-dir")?.addEventListener("click", chooseBackupFolder);
    $("#btn-export-dir")?.addEventListener("click", exportBackupToFolder);
    $("#list")?.addEventListener("click", async (e)=>{
      const t=e.target; const act=t.dataset.act; const id=t.dataset.id; if(!act) return;
      const item=state.vault.find(x=>x.id===id);
      if(act==="copy-user") await copyToClipboard(item.username);
      if(act==="copy-pass") await copyToClipboard(item.password);
      if(act==="edit") openEntry(id);
      if(act==="del") await deleteEntry(id);
      if(act==="open" && item.url) window.open(item.url, "_blank", "noopener,noreferrer");
    });

    if(!window.isSecureContext){
      console.warn("Biometrics and Service Worker need HTTPS or localhost.");
    }
    decideScreen().catch(err=>{ console.error(err); showOnboarding(); });
  });
})();