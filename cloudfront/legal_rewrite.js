function handler(event) {
  var request = event.request;
  var uri = request.uri;

  // Keep root "/" as-is; default_root_object handles it.
  if (uri === "/") return request;

  // If it looks like a file request (has a dot in last path segment), do nothing.
  var lastSlash = uri.lastIndexOf("/");
  var lastSegment = uri.substring(lastSlash + 1);
  if (lastSegment.indexOf(".") !== -1) {
    return request;
  }

  // If missing trailing slash, redirect to add it:
  // /brand  ->  /brand/
  if (!uri.endsWith("/")) {
    var location = uri + "/";

    // Preserve query string if present
    var qs = request.querystring;
    var parts = [];
    for (var k in qs) {
      if (!qs.hasOwnProperty(k)) continue;
      var v = qs[k];
      // v can be {value:"..."} or {multiValue:[{value:"..."}...]}
      if (v.multiValue) {
        for (var i = 0; i < v.multiValue.length; i++) {
          parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(v.multiValue[i].value));
        }
      } else if (v.value !== undefined) {
        parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(v.value));
      }
    }
    if (parts.length > 0) location += "?" + parts.join("&");

    return {
      statusCode: 301,
      statusDescription: "Moved Permanently",
      headers: {
        "location": { "value": location }
      }
    };
  }

  // Has trailing slash: /brand/ -> /brand/index.html
  request.uri = uri + "index.html";
  return request;
}
