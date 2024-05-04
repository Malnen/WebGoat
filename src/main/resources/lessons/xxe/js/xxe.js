// JavaScript function to add CSRF token data to the form
function addCsrfToken(formData) {
    var csrfToken = $('meta[name="_csrf"]').attr('content');
    var csrfHeader = $('meta[name="_csrf_header"]').attr('content');
    formData.append(csrfHeader, csrfToken);
}

// Update the simpleXXE function to add CSRF token
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

// Update other XXE functions similarly

// Update AJAX request to include CSRF token
function getComments(field) {
    var csrfToken = $('meta[name="_csrf"]').attr('content');
    var csrfHeader = $('meta[name="_csrf_header"]').attr('content');
    $.ajax({
        url: "xxe/comments",
        method: "GET",
        headers: {
            [csrfHeader]: csrfToken
        },
        success: function (result, status) {
            $(field).empty();
            for (var i = 0; i < result.length; i++) {
                var comment = html.replace('USER', result[i].user);
                comment = comment.replace('DATETIME', result[i].dateTime);
                comment = comment.replace('COMMENT', result[i].text);
                $(field).append(comment);
            }
        }
    });
}
