let myPort = browser.runtime.connect({name:"port-from-error-cs"});

function setMsg(message) {
    document.getElementById("errormsg").innerHTML=message;
}

document.getElementById("btOk").onclick = function() {
    browser.runtime.sendMessage({"closeError": true});
}

myPort.onMessage.addListener(function(m) {
    setMsg(m.error);
});
/* 
  message handler
*/
// browser.runtime.onMessage.addListener(message => {
//   if(message.error) {
//       setMsg(message.error);
//   }
// });
// window.addEventListener("message", (event) => {
//     if (event.source == window && event.data) {
//         console.log(event.data.error);
//     }
// });