const $=id=>document.getElementById(id);

const NOTES_DB="VaultTextNotesDB";
const NOTES_STORE="notes";
const NOTES_VERSION=1;
let editingNoteId=null;
let authResolver=null;
let deleteTimer=null;
let resetTimer=null;

function toast(message){
  const e=$("toast");
  e.textContent=message;
  e.classList.add("show");
  clearTimeout(window.__toastTimer);
  window.__toastTimer=setTimeout(()=>e.classList.remove("show"),2800);
}

function clean(e){ e.value=e.value.replace(/\D/g,"").slice(0,6); }
["setupTotp","noteTotp","totpEncrypt","totpDecrypt","authTotp"].forEach(id=>{
  $(id).addEventListener("input",()=>clean($(id)));
});

function openNotesDB(){
  return new Promise((resolve,reject)=>{
    const r=indexedDB.open(NOTES_DB,NOTES_VERSION);
    r.onupgradeneeded=()=>{
      const db=r.result;
      if(!db.objectStoreNames.contains(NOTES_STORE)){
        const store=db.createObjectStore(NOTES_STORE,{keyPath:"id"});
        store.createIndex("updatedAt","updatedAt");
      }
    };
    r.onsuccess=()=>resolve(r.result);
    r.onerror=()=>reject(r.error);
  });
}

async function getAllNotes(){
  const db=await openNotesDB();
  return new Promise((resolve,reject)=>{
    const r=db.transaction(NOTES_STORE,"readonly").objectStore(NOTES_STORE).getAll();
    r.onsuccess=()=>resolve(r.result.sort((a,b)=>b.updatedAt-a.updatedAt));
    r.onerror=()=>reject(r.error);
  });
}

async function getNote(id){
  const db=await openNotesDB();
  return new Promise((resolve,reject)=>{
    const r=db.transaction(NOTES_STORE,"readonly").objectStore(NOTES_STORE).get(id);
    r.onsuccess=()=>resolve(r.result||null);
    r.onerror=()=>reject(r.error);
  });
}

async function putNote(note){
  const db=await openNotesDB();
  return new Promise((resolve,reject)=>{
    const r=db.transaction(NOTES_STORE,"readwrite").objectStore(NOTES_STORE).put(note);
    r.onsuccess=()=>resolve();
    r.onerror=()=>reject(r.error);
  });
}

async function deleteNoteFromDB(id){
  const db=await openNotesDB();
  return new Promise((resolve,reject)=>{
    const r=db.transaction(NOTES_STORE,"readwrite").objectStore(NOTES_STORE).delete(id);
    r.onsuccess=()=>resolve();
    r.onerror=()=>reject(r.error);
  });
}

async function clearNotesDB(){
  const db=await openNotesDB();
  return new Promise((resolve,reject)=>{
    const r=db.transaction(NOTES_STORE,"readwrite").objectStore(NOTES_STORE).clear();
    r.onsuccess=()=>resolve();
    r.onerror=()=>reject(r.error);
  });
}

function formatDate(ts){
  return new Intl.DateTimeFormat("ru-RU",{day:"2-digit",month:"2-digit",year:"numeric",hour:"2-digit",minute:"2-digit"}).format(new Date(ts));
}

async function renderNotes(){
  const list=$("notesList");
  const empty=$("emptyNotes");
  try{
    const notes=await getAllNotes();
    list.innerHTML="";
    empty.classList.toggle("hidden",notes.length!==0);
    for(const note of notes){
      const button=document.createElement("button");
      button.className="note-item";
      button.type="button";
      button.dataset.id=note.id;
      button.innerHTML=`<span class="note-title"></span><span class="note-meta">Изменено ${formatDate(note.updatedAt)}</span><span class="note-lock">⌕</span>`;
      button.querySelector(".note-title").textContent=note.title;
      button.onclick=()=>openStoredNote(note.id);
      list.appendChild(button);
    }
  }catch(e){toast("Не удалось загрузить заметки.");}
}

function showView(id){
  document.querySelectorAll(".view").forEach(v=>v.classList.add("hidden"));
  $(id).classList.remove("hidden");
  document.querySelectorAll(".nav-btn").forEach(b=>b.classList.toggle("active",b.dataset.view===id));
}

function resetEditor(){
  editingNoteId=null;
  $("editorMode").textContent="Новая заметка";
  $("noteTitle").value="";
  $("noteText").value="";
  $("noteTotp").value="";
  $("saveNoteBtn").textContent="Создать шифр-код и сохранить";
  $("deleteNoteBtn").classList.add("hidden");
  $("revealCipherBtn").classList.add("hidden");
  $("cipherReveal").classList.add("hidden");
  $("cipherReveal").value="";
}

function startNewNote(){
  resetEditor();
  showView("editorView");
  $("noteTitle").focus();
}

function openAuthModal(title,description){
  $("authTitle").textContent=title;
  $("authDescription").textContent=description;
  $("authTotp").value="";
  $("authModal").classList.remove("hidden");
  setTimeout(()=>$("authTotp").focus(),50);
  return new Promise(resolve=>{
    authResolver=resolve;
  });
}

function closeAuthModal(){
  $("authModal").classList.add("hidden");
  $("authTotp").value="";
  authResolver=null;
}

$("authConfirmBtn").onclick=async()=>{
  if(!authResolver)return;
  const resolver=authResolver;
  try{
    const ok=await VaultCrypto.verifyTotp($("authTotp").value);
    if(!ok){toast("Неверный или просроченный код Google Authenticator.");return;}
    closeAuthModal();
    resolver(true);
  }catch(e){toast(e.message);}
};

$("authCancelBtn").onclick=()=>{
  if(authResolver){
    const resolver=authResolver;
    closeAuthModal();
    resolver(false);
  }else closeAuthModal();
};

$("authTotp").addEventListener("keydown",e=>{
  if(e.key==="Enter")$("authConfirmBtn").click();
  if(e.key==="Escape")$("authCancelBtn").click();
});

async function openStoredNote(id){
  try{
    const note=await getNote(id);
    if(!note)return toast("Заметка не найдена.");
    const ok=await openAuthModal("Открыть заметку","Введите актуальный код Google Authenticator для расшифровки.");
    if(!ok)return;
    const text=await VaultCrypto.decryptText(note.cipher,noteAuthCodeLast);
    editingNoteId=note.id;
    $("editorMode").textContent="Редактирование заметки";
    $("noteTitle").value=note.title;
    $("noteText").value=text;
    $("noteTotp").value="";
    $("saveNoteBtn").textContent="Сохранить изменения";
    $("deleteNoteBtn").classList.remove("hidden");
    $("revealCipherBtn").classList.remove("hidden");
    $("cipherReveal").classList.add("hidden");
    $("cipherReveal").value="";
    showView("editorView");
    $("noteText").focus();
  }catch(e){toast(e.message||"Не удалось открыть заметку.");}
}

let noteAuthCodeLast="";
// Preserve the validated code only long enough to decrypt the note that was just authorized.
$("authConfirmBtn").onclick=async()=>{
  if(!authResolver)return;
  const resolver=authResolver;
  const code=$("authTotp").value;
  try{
    if(!/^\d{6}$/.test(code)){toast("Введите ровно 6 цифр.");return;}
    const ok=await VaultCrypto.verifyTotp(code);
    if(!ok){toast("Неверный или просроченный код Google Authenticator.");return;}
    noteAuthCodeLast=code;
    closeAuthModal();
    resolver(true);
  }catch(e){toast(e.message);}
};

$("revealCipherBtn").onclick=async()=>{
  if(!editingNoteId)return;
  try{
    const note=await getNote(editingNoteId);
    if(!note){toast("Заметка не найдена.");return;}
    $("cipherReveal").value=note.cipher;
    $("cipherReveal").classList.remove("hidden");
    await navigator.clipboard.writeText(note.cipher);
    toast("Шифр-код показан и автоматически скопирован в буфер обмена.");
  }catch{
    toast("Не удалось скопировать шифр-код в буфер обмена.");
  }
};

$("newNoteBtn").onclick=startNewNote;
$("backToNotesBtn").onclick=()=>{
  resetEditor();
  showView("notesView");
  renderNotes();
};

$("saveNoteBtn").onclick=async()=>{
  const title=$("noteTitle").value.trim();
  const text=$("noteText").value;
  if(!title){toast("Введите заголовок.");$("noteTitle").focus();return;}
  if(!text){toast("Введите текст заметки.");$("noteText").focus();return;}
  const code=$("noteTotp").value;
  try{
    const cipher=await VaultCrypto.encryptText(text,code);
    const now=Date.now();
    const note=editingNoteId?await getNote(editingNoteId):null;
    const saved={
      id:editingNoteId||crypto.randomUUID(),
      title,
      cipher,
      createdAt:note?.createdAt||now,
      updatedAt:now
    };
    await putNote(saved);
    toast(editingNoteId?"Изменения сохранены":"Заметка создана и зашифрована");
    resetEditor();
    showView("notesView");
    await renderNotes();
  }catch(e){toast(e.message);}
};

$("deleteNoteBtn").onclick=async()=>{
  if(!editingNoteId)return;
  const ok=await openAuthModal("Удаление заметки","Введите актуальный код Google Authenticator. После проверки появится подтверждение удаления.");
  if(!ok)return;
  startDeleteCountdown();
};

function startDeleteCountdown(){
  $("deleteModal").classList.remove("hidden");
  const btn=$("deleteConfirmBtn");
  let seconds=3;
  btn.disabled=true;
  btn.textContent=`Удалить безвозвратно (${seconds})`;
  clearInterval(deleteTimer);
  deleteTimer=setInterval(()=>{
    seconds--;
    if(seconds<=0){
      clearInterval(deleteTimer);
      btn.disabled=false;
      btn.textContent="Удалить безвозвратно";
    }else btn.textContent=`Удалить безвозвратно (${seconds})`;
  },1000);
}

$("deleteCancelBtn").onclick=()=>{
  clearInterval(deleteTimer);
  $("deleteModal").classList.add("hidden");
};

$("deleteConfirmBtn").onclick=async()=>{
  if($("deleteConfirmBtn").disabled||!editingNoteId)return;
  const id=editingNoteId;
  try{
    await deleteNoteFromDB(id);
    clearInterval(deleteTimer);
    $("deleteModal").classList.add("hidden");
    resetEditor();
    showView("notesView");
    await renderNotes();
    toast("Заметка безвозвратно удалена.");
  }catch(e){toast("Не удалось удалить заметку.");}
};

async function resetSecret(){
  const ok=await openAuthModal(
    "Сброс TOTP-ключа",
    "Введите актуальный код Google Authenticator. После успешной проверки начнётся 10-секундная защита перед удалением ключа и всех заметок."
  );
  if(!ok)return;
  startResetCountdown();
}

function startResetCountdown(){
  $("resetModal").classList.remove("hidden");
  const btn=$("resetConfirmBtn");
  let seconds=10;
  btn.disabled=true;
  btn.textContent=`Сбросить всё безвозвратно (${seconds})`;
  clearInterval(resetTimer);
  resetTimer=setInterval(()=>{
    seconds--;
    if(seconds<=0){
      clearInterval(resetTimer);
      btn.disabled=false;
      btn.textContent="Сбросить всё безвозвратно";
    }else btn.textContent=`Сбросить всё безвозвратно (${seconds})`;
  },1000);
}

$("resetCancelBtn").onclick=()=>{
  clearInterval(resetTimer);
  $("resetModal").classList.add("hidden");
};

$("resetConfirmBtn").onclick=async()=>{
  if($("resetConfirmBtn").disabled)return;
  try{
    await clearNotesDB();
    await VaultCrypto.dbDelete();
    clearInterval(resetTimer);
    $("resetModal").classList.add("hidden");
    toast("TOTP-ключ и все заметки безвозвратно удалены.");
    setTimeout(()=>location.reload(),500);
  }catch(e){
    toast("Не удалось выполнить полный сброс.");
  }
};

async function refresh(){
  const ok=await VaultCrypto.hasSecret();
  $("setupPanel").classList.toggle("hidden",ok);
  $("secretPanel").classList.add("hidden");
  $("bottomNav").classList.toggle("hidden",!ok);
  document.querySelectorAll(".view").forEach(v=>v.classList.add("hidden"));
  if(ok){
    showView("notesView");
    await renderNotes();
  }
}
let enrollmentSecret=null;
$("createSecretBtn").onclick=async()=>{
  try{
    enrollmentSecret=await VaultCrypto.createEnrollment();
    $("secretDisplay").value=enrollmentSecret;
    $("secretPanel").classList.remove("hidden");
    $("setupPanel").classList.add("hidden");
    toast("Секрет создан. Добавьте его в Google Authenticator.");
  }catch(e){toast(e.message);}
};
$("confirmSecretBtn").onclick=async()=>{
  try{
    if(!(await VaultCrypto.verifyTotp($("setupTotp").value)))throw Error("Код не совпадает. Проверьте ключ в Google Authenticator.");
    $("secretPanel").classList.add("hidden");
    $("bottomNav").classList.remove("hidden");
    showView("notesView");
    await renderNotes();
    toast("Google Authenticator успешно привязан");
  }catch(e){toast(e.message);}
};
$("copySecret").onclick=async()=>{
  try{await navigator.clipboard.writeText($("secretDisplay").value);toast("Ключ скопирован");}catch{toast("Не удалось скопировать");}
};
$("deleteSecretBtn").onclick=resetSecret;
$("resetFromSettingsBtn").onclick=resetSecret;

document.querySelectorAll(".nav-btn").forEach(b=>b.onclick=()=>{
  if(editingNoteId!==null && b.dataset.view!=="editorView"){
    // Leaving the editor intentionally discards unsaved changes.
    resetEditor();
  }
  showView(b.dataset.view);
  if(b.dataset.view==="notesView")renderNotes();
});

$("encryptBtn").onclick=async()=>{
  try{
    $("cipherOut").value=await VaultCrypto.encryptText($("plainText").value,$("totpEncrypt").value);
    $("encryptResult").classList.remove("hidden");
    toast("Зашифровано");
  }catch(e){toast(e.message);}
};
$("decryptBtn").onclick=async()=>{
  try{
    $("plainOut").value=await VaultCrypto.decryptText($("cipherIn").value,$("totpDecrypt").value);
    $("decryptResult").classList.remove("hidden");
    toast("Расшифровано");
  }catch(e){
    $("decryptResult").classList.add("hidden");
    toast(e.message);
  }
};
async function copy(id){
  try{await navigator.clipboard.writeText($(id).value);toast("Скопировано");}
  catch{toast("Буфер обмена недоступен");}
}
$("copyCipher").onclick=()=>copy("cipherOut");
$("copyPlain").onclick=()=>copy("plainOut");
$("downloadCipher").onclick=()=>{
  const b=new Blob([$("cipherOut").value],{type:"text/plain;charset=utf-8"});
  const a=document.createElement("a");
  a.href=URL.createObjectURL(b);
  a.download="vaulttext-code.txt";
  a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href),1000);
};

if("serviceWorker"in navigator){
  window.addEventListener("load",()=>navigator.serviceWorker.register("./sw.js").catch(()=>{}));
}
refresh();
