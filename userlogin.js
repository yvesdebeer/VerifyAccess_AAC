importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.ibm.security.access.server_connections.ServerConnectionFactory);
importClass(Packages.com.tivoli.am.fim.base64.BASE64Utility);
importPackage(Packages.com.ibm.security.access.httpclient);

// Custom Base64 encoding function
function base64Encode(input) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var str = input;
    var output = '';

    for (var block = 0, charCode, i = 0, map = chars; str.charAt(i | 0) || (map = '=', i % 1); output += map.charAt(63 & block >> 8 - i % 1 * 8)) {
        charCode = str.charCodeAt(i += 3 / 4);

        if (charCode > 0xFF) {
            throw new Error("'btoa' failed: The string to be encoded contains characters outside of the Latin1 range.");
        }

        block = block << 8 | charCode;
    }

    return output;
}

function getWebServiceData(name) {
    IDMappingExtUtils.traceString("Entering getWebServiceData(" + name + ")");

    // Get the Web Server Connection Details
    var wconn = ServerConnectionFactory.getWebConnectionByName(name);
    if (wconn == null) {
        IDMappingExtUtils.traceString("Failed to get connection data for " + name);
        var result = "getFailed";
    } else {
        var ws_url = wconn.getUrl() + "";
        var ws_user = wconn.getUser() + "";
        var ws_pwd = wconn.getPasswd() + "";
        IDMappingExtUtils.traceString("ws_url=" + ws_url + ",ws_user=" + ws_user + ",ws_pwd=Sorry, cannot show here");
        var result = "ok";
    }
    // return an object with 4 labels: url, password, user and result.
    return { url: ws_url, password: ws_pwd, user: ws_user, result: result };
}

// Get and URL, username and password
var wsdata = getWebServiceData("External Auth Server");
if (wsdata == null || wsdata.result != "ok") {
    IDMappingExtUtils.traceString("getWebServiceData failed");
    // Handle failure accordingly
    success.setValue(false); // Ensure success is set to false
} else {
    var bauser = wsdata.user;
    var bapassword = wsdata.password;
    var endpoint = wsdata.url;
}


// Get username from request parameters  
var username = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username");
IDMappingExtUtils.traceString("username from request: " + username);


if (username != null) {     // username found, set this as the user to login     
    context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", username);

    // Construct the request body
    var RequestBody = '{"name": "' + username + '", "authenticated": "true"}';

    // Encode the username and password in Base64
    var basicAuth = 'Basic ' + base64Encode(bauser + ':' + bapassword);

    // Define the headers and add the Authorization header
    var headers = new Headers();
    headers.addHeader("Content-Type", "application/json");
    headers.addHeader("Authorization", basicAuth);

    /**   
    * httpPost(String url, Map headers, String body,String httpsTrustStore,   
    * String basicAuthUsername,String basicAuthPassword, String   
    * clientKeyStore,String clientKeyAlias);
    */

    var hr = HttpClient.httpPost(endpoint, headers, RequestBody, null, null, null, null, null);
    if (hr != null) {
        var code = hr.getCode(); // this is int   
        var body = hr.getBody(); // this is java.lang.String 

        IDMappingExtUtils.traceString("code: " + code);
        IDMappingExtUtils.traceString("body: " + body);

        // sanity check the response code and body - this is "besteffort"   
        if (code != 200) {
            IDMappingExtUtils.throwSTSException("Bad response code from QRadar HTTP Receiver: " + code);
        }

    }
    success.setValue(true);
}

