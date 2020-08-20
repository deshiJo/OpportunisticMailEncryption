// export {smtpConnect};
// var net = require('net'); 

/*
If we sending a message and opportunistc encryption is activated:
- we check 
*/
let socket = null;
const regex_mail = "";
const OK_RECV = "OK RECV";
const OK_SERVER = "OK SERVER";
const FAIL = "FAIL";
const SUCCESS = "SUCCESS"
const TIMEOUT = "TIMEOUT";
const NOT_SUPPORTED = "NOT_SUPPORTED";
const CERT_RESPONSE = "CERT: ";
const TLS_ERROR = "TLS_ERROR";
const NOT_TRUSTED = "NOT_TRUSTED";
const WHITESPACE = " ";
var running = true;
//TODO: put constants in a seperat file, to share these with background.js, connection.js,...


// var scope = ChromeUtils.import("resource://foo/modules/Foo.jsm"); // scope.Foo…

//https://stackoverflow.com/questions/21310157/building-a-simple-smtp-client-using-websockets
//https://developer.mozilla.org/en-US/docs/Mozilla/Mozilla_Port_Blocking 25 is blocked !
//websocket wont work !

//https://stackoverflow.com/questions/45291765/how-to-run-a-external-executable-with-firefox-web-extensions/45312003
//https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging
//maybe use this : https://developer.mozilla.org/en-US/docs/Mozilla/JavaScript_code_modules/Using
//https://aticleworld.com/ssl-server-client-using-openssl-in-c/



//native apps ::: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_manifests#Manifest_location
//https://github.com/mdn/webextensions-examples/tree/master/native-messaging
//https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/runtime


//LESE DAS + GEKO: 
//https://developer.thunderbird.net/add-ons/updating/tb68/changes
//https://developer.thunderbird.net/add-ons/updating/tb78
//ALLES ANDERE SCHEINT VERALTET !?
function smtpConnect(recipient_Addr, outgoing_SMTP) {

    //TODO: reject the promise on error ?!
    let result = new Promise(function(resolve,reject) {
        var port = browser.runtime.connectNative("smtp_client");
        // var outgoingSMTP = "mail1.de:25";
        // var recipientAddr = "joachim@mail1";
        var recipientAddr = recipient_Addr;
        var outgoingSMTP = outgoing_SMTP[0]+":"+outgoing_SMTP[1];
        var finished = false;
        running = true;
        //30 sec timeout
        var timeout = 30000;
        var recipient_cert = ""

        //set timeout for the request
        setTimeout(function() { 
            if(!finished && running) {
                error_message = TIMEOUT;
                abort(port,"timout: abort", error_message);
            }
        }, timeout);

        //send outgoing server information and recipient address, to start the xcertreq
        console.log("start request:")
        console.log("   Sending recipient address: "+ recipientAddr);
        port.postMessage("RECV: " + recipientAddr);


        // port.postMessage(recipientAddr);
        // port.postMessage(outgoingSMTP);

        port.onMessage.addListener((response) => {
            // console.log("   Received: " + response);
            if(response === OK_RECV) {
                console.log("   Received: " + response);
                console.log("   Sending outgoing server: "+ outgoingSMTP);
                console.log("SERVER: "+ outgoingSMTP);
                port.postMessage("SERVER: "+ outgoingSMTP);
            }
            else if(response === OK_SERVER) {
                console.log("   Received: " + response);
            }
            else if(response.startsWith(FAIL)) {
                console.log("   Received: " + response);
                //something went wrong: abort
                error_message = FAIL;
                abort(port,"FAIL response from client: abort",error_message);
            }
            else if(response.startsWith(CERT_RESPONSE)) {
                console.log("   Received: " + response);
                finished=true;
                splittedResponse = response.split(WHITESPACE);
            }
            else if (response.startsWith("OK: ")) {
                splitted = response.split("OK: ");
                if(splitted.length > 1) {
                    console.log("   "+ "SMTP response: " + splitted[1]);
                }
            }
            else if (response.startsWith(TLS_ERROR)) {
                splitted = response.split(TLS_ERROR);
                if (splitted.length > 1) {
                    console.log("   ERROR:"+ splitted[1]);

                }
                error_message = TLS_ERROR;
                abort(port, "STARTTLS exchange error", error_message);
            }
            else if (response === NOT_SUPPORTED) {
                console.log("   Received: "+ response);
                error_message = NOT_SUPPORTED;        
                abort(port, "STARTTLS or XCERTREQ not supported by the recipient server or outgoing server: abort", error_message);
            }
            else if (response.startsWith(SUCCESS)) {
                console.log(response);
                splitted = response.split(SUCCESS+": 250 XCERTREQ ");
                if (splitted.length > 1 ) {
                    finished = true;

                    //only for debugging:
                    // abort(port, "success", "");

                    //TODO now use the certificate for encryption and send mail encrypted
                    //console.log(splitted[1]);
                    resolve(splitted[1]);
                }
                else {
                    //TODO ERROR 
                }

            } else {
                //something went wrong: abort
                console.log("   "+ "ERROR:" + response);
                error_message = "DEFAULT";
                abort(port,"wrong response from smtp client: abort",error_message);
            }
        });
    });
    return result;
}

function abort(port, log_message, error_message) {
    //TODO: show error message to user
    running = false;
    console.log(log_message);
    port.disconnect()
    abortProtocol(error_message);
}


    // socket = mozTCPSocket.open('localhost', 8080);

    // socket.ondata = function (event) {
    //     if (typeof event.data === 'string') {
    //         console.log('Get a string: ' + event.data);
    //     } else {
    //         console.log('Get a Uint8Array');
    //     }
    // }

    // var outgoingSMTP = "testmail"
    // socket = new WebSocket('localhost:8080');

    // socket.addEventListener('open', function (event) {
    //     alert("[open] Connection established");
    //     alert("Sending to server");
    //     xcertReq(socket);
    // });

    // // Listen for messages
    // socket.addEventListener('message', function (event) {
    //     console.log('Message from server ', event.data);

    // });

    // var socket = net.createConnection(25, 'testmail');
    // console.log('Socket created.');
    // socket.on('data', function(data) {
    //     // Log the response from the HTTP server.
    //     console.log('RESPONSE: ' + data);
    // }).on('connect', function() {
    //     // Manually write an HTTP request.
    //     socket.write("GET / HTTP/1.0\r\n\r\n");
    // }).on('end', function() {
    //     console.log('DONE');
    // });

