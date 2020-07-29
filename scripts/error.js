let myPort = browser.runtime.connect({name:"port-from-error-cs"});

function setMsg(message) {
    document.getElementById("errormsg").innerHTML=message;
}

document.getElementById("btOk").onclick = function() {
    myPort.postMessage({"closeError": true});
}

myPort.onMessage.addListener(function(m) {
    console.log("message received");
    setMsg(m.error);
});
