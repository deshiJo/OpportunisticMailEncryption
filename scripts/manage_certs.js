/**
 * modules
 */

var { ExtensionParent } = ChromeUtils.import("resource://gre/modules/ExtensionParent.jsm");
var extension = ExtensionParent.GlobalManager.getExtension("experiment@sample.extensions.thunderbird.net");
var { ExtensionCommon } = ChromeUtils.import("resource://gre/modules/ExtensionCommon.jsm");
var { Services } = ChromeUtils.import("resource://gre/modules/Services.jsm");

// var { MailServices } = ChromeUtils.import("resource:///modules/MailServices.jsm");

var certificateManagement = class extends ExtensionCommon.ExtensionAPI {
  getAPI(context) {
    return {
      certificateManagement: {

        /**
         * save the certificate for the corresponding recipient address
         * @param {} recipientID 
         * @param {*} certificate 
         */
        import_cert(recipientID, certificate) {
            
            //TODO: save the certificate 


        },

        /**
         * get the current ougoing smtp server for the given identityId
         * @param {*} identityId 
         */
        get_smtp_server(identityId) {
            console.log("extract ougoing smtp server");
            // var currentAccount = PrefValue("mail.accountmanager.currentAccount");
            // Services.wm.getMostRecentWindow("mail:3pane").alert("Hello !");
            // console.log(acctMgr.accounts)
            var acctMgr = Components.classes["@mozilla.org/messenger/account-manager;1"]
                        .getService(Components.interfaces.nsIMsgAccountManager);
            var smtpMgr = Components.classes["@mozilla.org/messengercompose/smtp;1"]
                        .getService(Components.interfaces.nsISmtpService);
                
            // var smtpMgr = Components.classes["@mozilla.org/messengercompose/smtp;1"];

            // console.log(acctMgr);
            console.log("get Identity object for: " + identityId);
            var identity = acctMgr.getIdentity(identityId);
            // console.log(identity);

            console.log("extract smtp with identity object");
            var out = {};
            smtpMgr.getServerByIdentity(identity, out);
            var server = out.value;
            // console.log(server);
            // console.log(server.hostname);
            // console.log(server.port);
            var result = [server.hostname, server.port];

            return result;
        }
        /**
         * Place more functions here
         */
      }
    }
  }
};
