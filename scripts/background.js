//icon from https://www.iconfinder.com/iconsets/bitsies

let promiseMap = new Map();
let loadingWindowResolve;

let loadingWindowID;
var activated = true;
browser.composeAction.setBadgeText({
  text:"✔"
});


/* 
  message handler
*/
browser.runtime.onMessage.addListener(message => {
  if(message.abort) {
    abortProtocol();
  }
});

/*
  called if abort button is pressed in loader.html
*/
function abortProtocol() {
  console.log("abort certificate request");
  let resolve = loadingWindowResolve;
  if (!resolve) {
    console.log("resolve not defined!");
    //This should not happen !!
    return
  }
  console.log("cancel message send");
  browser.windows.remove(loadingWindowID);
  resolve({ cancel: true });
}

/*
  get current window
*/
function getCurrentWindow() {
    return browser.windows.getCurrent();
}

/*
  If the protocol is activated in the UI, interrupt message send process and start the certificate request.
  The message send process is aborted, if the user hit the abort button.
  TODO timeout ? 
*/
browser.compose.onBeforeSend.addListener(() => {
  // browser.composeAction.enable(tab.id);
  // browser.composeAction.openPopup();
  if(activated) {
    console.log("Event triggered");
    loadingWindow = browser.windows.create({
      allowScriptsToClose: true,
      url: "../popup/loader.html",
      type: "panel",
      width: 300,
      height: 300,
    });
    loadingWindow.then(onCreated);
    loadingWindow.catch((error) => {
      console.error(error);
    })
    onSendPerformed();
    return new Promise(resolve => {
      // promiseMap.set(loadingWindowID, resolve);
      loadingWindowResolve = resolve;
    });
  } else {
    return {
      "cancel": false,
    };
  }
  
});

// window.addEventListener('load', (event) => {
//   var composewindow = document.getElementById("msgcomposeWindow");
//   console.log(composewindow);
//   var sendButton = window.document.getElementById("button-newmsg");
//   console.log(document.querySelectorAll('[id]'));
//   console.log(sendButton);
//   if (sendButton) {
//     console.log("button element FOUND !!!cos(0)")
//     let attr = sendButton.getAttribute("oncommand");
//     sendButton.setAttribute("oncommand", "OnSendPerformed(); "+ attr+ "; ");
//   } else {
//     console.log("button element id not found");
//   }
// //   console.log('page is fully loaded');
// //   alert("TEEEEEST");
// //   // window.addEventListener("compose-send-message", function(event) {
// //   //   console.log('send message event'); 
// //   // }, true);
// });


// var objoptions = {
//   onload: async function(){
//     console.log("FIRED");
//     var sendButton = document.getElementById("button-send");
//     // var composer = document.getElementById('msgcomposeWindow');
//     // console.log(browser.windows);
//     // console.log(composewindow);
//     // var sendButton = document.getElementById("button-newmsg");
//     // console.log(document.querySelectorAll('[id]'));
//     console.log(sendButton);
//   }
// }
// window.addEventListener('compose-message-send', objoptions.onload, true);

// window.addEventListener("compose-window-init", (event) => {
//   Applications.console.log("Event triggered");
//   var creating = browser.windows.create({
//     allowScriptsToClose: true,
//     url: "../popup/loader.html",
//     type: "panel",
//     width: 80,
//     height: 250,
//   });
//   creating.then(onCreated, onError);

//   //check if certificate already present
//   var present = false; //TODO
//   if (present) {
//     //yes: check revocation

//   } else {
//     //No:create connection to outgoing smtp server and send xcertreq
//     smtpConnect();
//   }
//   // onSendPerformed(event);
// }, true);





//trigger cert req on message send 
// window.addEventListener('compose-send-message', onSendPerformed, true);
// window.addEventListener('compose-window-close', onSendPerformed, true);
function onSendPerformed() {  
  //check if certificate already present
  var present = false; //TODO
  if (present) {
    //yes: check revocation

  } else {
    //No:create connection to outgoing smtp server and send xcertreq
    // smtpConnect();
  }
}


/*
On click toggle opportunistic encryption
*/
browser.composeAction.onClicked.addListener(() => {
  //Toggle button. Activate/deactivate opportunistic encryption
  activated = !activated;
  
  //Toggle color of the button
  // console.log(browser.windows.getAll({
  //   populate: true,
  // }));

  //only for testing
  // smtpConnect();

  if(activated) {

    console.log("activate opportunistic encryption mode");
    //browser.composeAction.setBadgeBackgroundColor("#FF0000");
    browser.composeAction.setTitle({
      title: "on"
    });
    browser.composeAction.setBadgeText({
      //https://graphemica.com/%E2%9C%94
      text:"✔"
    });
  } else {
    console.log("deactivate opportunistic encryption mode");
    //browser.composeAction.setBadgeBackgroundColor("#FFFFFF");
    browser.composeAction.setTitle({
      title: "off"
    });
    browser.composeAction.setBadgeText({
      //https://graphemica.com/%E2%9C%97
      text:"✗"
    });
  }
  //const gettingStoredSettings = browser.storage.local.get();
  //gettingStoredSettings.then(forget, onError);
});


//show "please wait" while request certificate
function onCreated(windowInfo) {
  loadingWindowID = windowInfo.id;
  // console.log(windowInfo);
  // var loadingWindow = browser.windows.get(windowInfo.id);
  console.log(`Created window: ${windowInfo.id}`);
  // console.log(loadingWindow.document.getElementById("btAbort"));
}

function onError(error) {
  console.log(`Error: ${error}`);
}



// browser.composeAction.onClicked.addListener(async (tab) => {
//     // Get the existing message.
//     let details = await browser.compose.getComposeDetails(tab.id);
//     console.log(details);
  
//     if (details.isPlainText) {
//       // The message is being composed in plain text mode.
//       let body = details.plainTextBody;
//       console.log(body);
  
//       // Make direct modifications to the message text, and send it back to the editor.
//       body += "\n\nSent from my Thunderbird";
//       console.log(body);
//       browser.compose.setComposeDetails(tab.id, { plainTextBody: body });
//     } else {
//       // The message is being composed in HTML mode. Parse the message into an HTML document.
//       let document = new DOMParser().parseFromString(details.body, "text/html");
//       console.log(document);
  
//       // Use normal DOM manipulation to modify the message.
//       let para = document.createElement("p");
//       para.textContent = "Sent from my Thunderbird";
//       document.body.appendChild(para);
  
//       // Serialize the document back to HTML, and send it back to the editor.
//       let html = new XMLSerializer().serializeToString(document);
//       console.log(html);
//       browser.compose.setComposeDetails(tab.id, { body: html });
//     }
//   });

