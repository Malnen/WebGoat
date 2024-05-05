// need custom js for this?

webgoat.customjs.idorViewProfile = function (data) {
    webgoat.customjs.jquery('#idor-profile').html(
            'name:' + data.name + '<br/>' +
            'color:' + data.color + '<br/>' +
            'size:' + data.size + '<br/>'
    );
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
