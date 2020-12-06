let myPort = browser.runtime.connect({name:"port-from-trust"});


document.getElementById("btTrust").onclick = function() {
    myPort.postMessage({"Abort": false});
}

document.getElementById("btAbort").onclick = function() {
    myPort.postMessage({"Abort": true});
}

