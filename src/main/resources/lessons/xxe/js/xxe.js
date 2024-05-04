webgoat.customjs.simpleXXE = function () {
    var commentInput = $("#commentInputSimple").val();
    var xml = '<?xml version="1.0"?>' +
            '<comment>' +
            '  <text>' + commentInput + '</text>' +
            '</comment>';
    var formData = new FormData();
    formData.append('xml', xml);
    addCsrfToken(formData); // Add CSRF token data
    return formData;
}

$(document).ready(function () {
    getComments('#commentsListBlind');
});



var html = '<li class="comment">' +
    '<div class="pull-left">' +
    '<img class="avatar" src="images/avatar1.png" alt="avatar"/>' +
    '</div>' +
    '<div class="comment-body">' +
    '<div class="comment-heading">' +
    '<h4 class="user">USER</h4>' +
    '<h5 class="time">DATETIME</h5>' +
    '</div>' +
    '<p>COMMENT</p>' +
    '</div>' +
    '</li>';

function getComments(field) {
    $.get("xxe/comments", function (result, status) {
        $(field).empty();
        for (var i = 0; i < result.length; i++) {
            var comment = html.replace('USER', result[i].user);
            comment = comment.replace('DATETIME', result[i].dateTime);
            comment = comment.replace('COMMENT', result[i].text);
            $(field).append(comment);
        }

    });
}
