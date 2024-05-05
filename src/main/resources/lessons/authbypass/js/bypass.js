// need custom js for this?

webgoat.customjs.onBypassResponse = function (data) {
    webgoat.customjs.jquery('#verify-account-form').hide();
    webgoat.customjs.jquery('#change-password-form').show();
}

var onViewProfile = function () {
    console.warn("on view profile activated")
    var csrfToken = $("meta[name='_csrf']").attr("content");
    var csrfHeader = $("meta[name='_csrf_header']").attr("content");
    var headers = {};
    headers[csrfHeader] = csrfToken;
    webgoat.customjs.jquery.ajax({
        method: "GET",
        url: "IDOR/profile",
        headers,
        contentType: 'application/json; charset=UTF-8'
    }).then(webgoat.customjs.idorViewProfile);
}
