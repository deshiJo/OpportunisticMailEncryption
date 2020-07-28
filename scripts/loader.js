document.getElementById("btAbort").onclick = function (){
    browser.runtime.sendMessage({"abort": true});
}
