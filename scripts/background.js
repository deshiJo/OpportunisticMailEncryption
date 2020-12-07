//icon from https://www.iconfinder.com/iconsets/bitsies

let promiseMap = new Map();
var activated = true;

let errorWindowID;
var currentErrorMessage = "";

let loadingWindowID;
let loadingWindowResolve;

let composeWindow;

let composeTabId;


/**
 * message ports for content scripts (i.e error.js)
 */
let portFromCSError;
let portFromTrustRequest;


browser.composeAction.setBadgeText({
  text:"✔"
});

/**
 * connection listener to connect to content scripts 
 */
browser.runtime.onConnect.addListener(connected);
function connected(p) {

  /**
   * listener for error.js
   */
  if(p.name=="port-from-error-cs") {
      portFromCSError = p;

      //add close listener for the window
      portFromCSError.onMessage.addListener(function(m) {
        if(m.closeError) {
          browser.windows.remove(errorWindowID);
          errorWindowID = null
        }
      });
      updateErrorMessageWindow();
  }
  if(p.name=="port-from-trust") {
	      portFromTrustRequest = p;
	      portFromTrustRequest.onMessage.addListener(function(m) {
		if(m.Abort) {
			browser.windows.remove(trustWindowID);
			trustWindowID = null;
			trustWindowResolve({"trust": false});
		} else {
			browser.windows.remove(trustWindowID);
			trustWindowID = null;
			trustWindowResolve({"trust": true});
		}
	      });
  }
  /**
   * add your listener here
   */
}

/**
 * sends a message to error.js, to update the displayed error message. 
 * The global variable currentErrorMessage is used as the displayed message
 */
function updateErrorMessageWindow() {
  if(currentErrorMessage && portFromCSError) {
    portFromCSError.postMessage({error: currentErrorMessage});
  } else {
    console.log("currentErrorMessage emtpy, or connection not estabilished yet. Use default error message.");
  }

}


/* 
  message handler for loader.js
  TODO: maybe use port connection like the connection to error.js
*/
browser.runtime.onMessage.addListener(message => {
  if(message.abort) {
    abortProtocol("");
  }
});

function closeLoadingWindowAndConitnueSending() {
  let resolve = loadingWindowResolve;
  if (!resolve) {
    console.log("resolve not defined!");
    //This should not happen !!
    return
  }
  browser.windows.remove(loadingWindowID);

  //TODO: USE CERTIFICATE TO ENCRYPT HERE

  resolve({ cancel: false });
}

/*
  called if abort button is pressed in loader.html
*/
function abortProtocol(error) {
  running = false;
  console.log("abort certificate request");
  let resolve = loadingWindowResolve;
  if (!resolve) {
    console.log("resolve not defined!");
    //This should not happen !!
    return
  }
  console.log("cancel message send");
  browser.windows.remove(loadingWindowID);
  if(error) {
    // currentErrorMessage = error;
    switch(error) {
      case NOT_SUPPORTED: 
        currentErrorMessage = "Opportunistic encryption not supported by your mail server or your recipient.\n"
            + "Try again or receive the public key manually";
        break;
      case FAIL: 
        currentErrorMessage = "Something went wrong, while requesting the certificate/key for the recipient.\n" ;
        break;
      case TIMEOUT:
        currentErrorMessage = "Timeout: Connection failed or Server is busy.\n"
            +"Try again laiter, or send the mail unencrypted if necessary."
        break;
      case TLS_ERROR:
        currentErrorMessage = "Error while starting tls connection\n. Try again or get recipient key manually, if this error occures again";
        break;
      case NOT_TRUSTED:
        currentErrorMessage = "Cant trust the certificate";
        break;
      case NO_CERT:
        currentErrorMessage = "No Certificate found for this user.\n";
      default:
        currentErrorMessage = "Something went wrong.";
        break;
    }
    errorMessage = browser.windows.create({
      allowScriptsToClose: true,
      url: "../popup/error.html",
      type: "panel",
      width: 300,
      height: 190,
    });
    errorMessage.then((errorWindow) => {
      /**
       * The window is created now. The content scipt error.js will now create a message connection to this script, handled in connected(p).
       * Make sure, to set the parameter currentErrorMessage before creating the window, because this 
       * variable is used as the displayed message on error.html
      */
      onCreated(errorWindow);
      errorWindowID = errorWindow.id;
    });
    errorMessage.catch((error) => {
      console.error(error);
    })
  }
  console.log("resolve");
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
      height: 250,
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

  var recipientPromise = extractRecipientAddressAndIdentityId();
  recipientPromise.then((details) => {
    var recipientAddress = details[0];
    var identityId = details[1];
    outgoing_server = browser.certificateManagement.get_smtp_server(identityId);

    outgoing_server.then((info) => {

      console.log(info);
      recipientCert = smtpConnect(recipientAddress, info);
      recipientCert.then((serverResponse) => {
        console.log("SERVER RESPONSE:" + serverResponse);
        cert = serverResponse.cert;
        domain_cert = serverResponse.domain;
        console.log(" CERT \n" + cert);
        console.log("DOMAIN CERT \n" + domain_cert);
        /**
         *check received certificate and send encrypted if possible
         */
        //var ok = browser.certificateManagement.import_cert(String(recipientAddress), cert, domain_cert);

        var dom_name = String(recipientAddress).split("@")[1];
        console.log("check if domain " + dom_name + " certificate is known");
        var known = browser.certificateManagement.checkDomainKnown("domain_" + dom_name, String(domain_cert));
        var cert_imported = false;
        //abortProtocol(NOT_TRUSTED);
        known.then((known) => {

          if (!known) {
            //domain new

            //user has to accept the new trust anchor TODO
            //popup where the user has to access the new connection
            trustMessage = browser.windows.create({
              allowScriptsToClose: true,
              url: "../popup/trust_request.html",
              type: "panel",
              width: 300,
              height: 190,
            });
            trustMessage.then((trustWindow) => {
              promiseTrustWindow = onCreateTrustWindow(trustWindow);
              promiseTrustWindow.then((userAnswer) => {
                //accept variable depends on user answer

                console.log("user answer " + userAnswer.trust);
                var accept = true
                accept = userAnswer.trust;

                if (!accept) {
                  console.log("user does not trust connection: abort sending");
                  abortProtocol(NOT_TRUSTED);
                  return;
                }
              });

            });
          }

          try {
            var success_import = browser.certificateManagement.import_cert(String(recipientAddress), cert, domain_cert);
            console.log("import and set encryption: " + success_import);
            cert_imported = success_import;
          } catch (e) {
            console.log("error importing certificates and enable encryption");
            console.log(e);
            abortProtocol();
            return;
          }
          closeLoadingWindowAndConitnueSending();
          if (cert_imported) {
            setTimeout(() => {
              var success_remove_user = browser.certificateManagement.remove_cert_user(String(recipientAddress));
              console.log("remove user success: " + success_remove_user);
            }, 2000);
          }
        });


	return;
	    //browser.certificateManagement.encryptMessage(domain_cert);
	    
      	    //closeLoadingWindowAndConitnueSending();
	//	  return;
	    var domain_added = browser.certificateManagement.addDomainCertificate(domain_cert);
	    domain_added.then((success) => {
	    	console.log("added domain cert " + dom_name + " " + success);
	    });

	    closeLoadingWindowAndConitnueSending();
	    //return;
	    			  if (known) {
				  console.log("old domain cert");
			  } else {
				  console.log("new domain cert");
				  //browser.certificateManagement.addDomainCertificate(domain_cert);
			  }

			  console.log("insert certificate with name : " + String(recipientAddress));
			  var ok = browser.certificateManagement.addUserCertificate(cert,String(recipientAddress));
			  ok.then((added) => {
				  closeLoadingWindowAndConitnueSending();

				  //ok = browser.certificateManagement.addDomainCertificate(domain_cert);
				  //var ok = browser.certificateManagement.addDomainCertificate(domain_cert);
				  // ok = false;
				  //abortProtocol(NOT_TRUSTED);
				  //return;
				  ok.then((value) => {
					  console.log("OK: " +value);
					  //value = true;
					  if(value) {
						  closeLoadingWindowAndConitnueSending();
						  console.log("now remove received certificate (necessary because of some import bugs)");
						  setTimeout(() => { 
							  var deleted = browser.certificateManagement.remove_cert_user(String(recipientAddress));
							  deleted.then((deleted) => {
								  console.log("deleted user cert");
							  });
						  },2000);
					  } else {
						  console.log("abort sending");
						  abortProtocol(NOT_TRUSTED);
					  }
				  });
			  });
		  });
          })
      });
}

/**
 * get the sender id from the compose window
 */
// function getComposeDetails2() {
//   //get compose windows
//   let composeWindow = browser.windows.getAll({
//     "populate": true,
//     "windowTypes": ["messageCompose"]
//   });
//   // let curr_Window = browser.windows.getCurrent({
//   //   "populate": true
//   // }
//   // let curr_tab = browser.tabs.getCurrent();
//   // curr_tab.then(() => {
//   //   console.log(curr_tab.id);
//   // });
//   composeWindow.then((composeWindow) => {
//     console.log(composeWindow);
//     if (composeWindow.length > 1) {
//       //TODO: handle multiple compose windows
//       console.log("error: multiple compose windows open")
//       return;
//     }
//     var tabs = composeWindow[0].tabs;
//     if (tabs.length > 1) {
//       //TODO handle multiple tabs
//       console.log("error: multple tabs in compose window");
//       return;
//     }
//     // browser.compose.getComposeDetails(25);
//     console.log("compose tab id: "+ tabs[0].id);
//     var composeDetails = browser.compose.getComposeDetails(tabs[0].id);
//     composeDetails.then((composeDetails) => {
//       console.log(composeDetails);
//     });
//     return composeDetails;
//   })
// }

function getComposeWindow() {
  let composeWindow = browser.windows.getAll({
    "populate": true,
    "windowTypes": ["messageCompose"]
  });
  return composeWindow;
}

function getComposeDetails(composeWindow) {
  //this tab is sometime undefined, although i call function in the .then method of the window promise ? 
  //TODO maybe fix this, if necessary 
  var tabs = composeWindow.tabs;
  console.log(tabs.length);
  if (tabs.length > 1) {
    //TODO handle multiple tabs
    console.log("error: multple tabs in compose window");
    return;
  }
  // browser.compose.getComposeDetails(25);
  console.log("compose tab id: "+ tabs[0].id);
  composeTabId = tabs[0].id;
  var composeDetails = browser.compose.getComposeDetails(tabs[0].id);
  composeDetails.then((composeDetails) => {
    console.log(composeDetails);
  });
  return composeDetails;
}

function getSenderID(composeDetails) {
  console.log("compose details : " + composeDetails.identityId);
  return composeDetails.identityId;
}


/**
 * get the recipient address and the current identity, used in the compose window
 */
function extractRecipientAddressAndIdentityId() {
  composeWindow = getComposeWindow();
  let result = new Promise(function(resolve,reject) {
        //set datastructure / map with identityID/sender and recipient
    composeWindow.then((composeWindow) => {
      if (composeWindow.length > 1) {
        //TODO: handle multiple compose windows
        console.log("error: multiple compose windows open")
        return;
      }
      var composeDetails = getComposeDetails(composeWindow[0]);
      composeDetails.then((composeDetails) => {
        
        // console.log(composeDetails.identityId);
        // console.log(composeDetails.to);
        resolve([composeDetails.to, composeDetails.identityId]);
        //search mail address from this identity. Docu says, that composeDetails has a field identity, but there is only identityId.
        //Change if this is fixed.
        
        // browser.accounts.get("account1").then((account) => {
        //   console.log(account);
        // });

        // browser.accounts.list().then((accounts) => {
          // accounts.forEach(function (arrayItem)
          // console.log(accounts);
        // })
      });
    });
  });
  return result;
  // let composeDetails = getComposeDetails();
}


/*
On click toggle opportunistic encryption
*/
browser.composeAction.onClicked.addListener(() => {
  //Toggle button. Activate/deactivate opportunistic encryption
  activated = !activated;

  // promise.then((result) => {
  //   console.log(result);
  // })


  //test get from; to; infos from compose window
  // var recipientPromise = extractRecipient();
  // recipientPromise.then((to)=> {
  //   console.log(to);
  //   recipientAddress = to;
  // });
  // let composeWindow = getComposeWindow();
  // composeWindow.then((composeWindow) => {
  //   if (composeWindow.length > 1) {
  //     //TODO: handle multiple compose windows
  //     console.log("error: multiple compose windows open")
  //     return;
  //   }
  //   var composeDetails = getComposeDetails(composeWindow[0]);
  //   composeDetails.then((composeDetails) => {
  //     new Promise((resolve) => {
  //       //set datastructure / map with identityID/sender and recipient
  //     });
  //     console.log(composeDetails.identityId);
  //     console.log(composeDetails.to);
  //   });
  // });
  // let composeDetails = getComposeDetails();

  //only for testing

  if(activated) {

    console.log("activate opportunistic encryption mode");
    // browser.tabs.executeScript(composeTabId, {
    //   code: "document.getElementById('menu_securityEncryptRequire_Toolbar').checked='true'; document.getElementById('menu_securityEncryptDisable_Toolbar').checked='false';"
    // });

    //browser.composeAction.setBadgeBackgroundColor("#FF0000");
    browser.composeAction.setTitle({
      title: "on"
    });
    browser.composeAction.setBadgeText({
      //https://graphemica.com/%E2%9C%94
      text:"✔"
    });

    //set require encryption true
    // document.getElementById('menu_securityEncryptRequire_Toolbar').checked='true';
    // document.getElementById('menu_securityEncryptDisable_Toolbar').checked='false';
    // document.getElementById('encTech_SMIME_Toolbar').checked='true';
    // document.getElementById('encTech_OpenPGP_Toolbar').checked='false';

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

function onCreateTrustWindow(trustWindow) {
	trustWindowID = trustWindow.id;
	return new Promise(resolve => {
      		// promiseMap.set(loadingWindowID, resolve);
      		trustWindowResolve = resolve;
    	});
}

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

