$(document).ready(function () {
    $("#postComment").on("click", function () {
        var commentInput = $("#commentInput").val();
        $.ajax({
            type: 'POST',
            url: 'CrossSiteScriptingStored/stored-xss',
            data: JSON.stringify({text: commentInput}),
            contentType: "application/json",
            dataType: 'json'
        }).then(
            function (result) {
                if (result.feedback) {
                    $('#stored-comment-feedback').text(polyglot.t(result.feedback) || '');
                }
                if (result.attemptWasMade && (result.assignmentCompleted || result.lessonCompleted)) {
                    $('#stored-comment-assignment i').removeClass('hidden');
                }
                if (result.feedback === 'xss-stored-comment-invalid') {
                    return;
                }
                getChallenges();
                $("#commentInput").val('');
            }
        ).fail(function () {
            $('#stored-comment-feedback').text('The comment could not be saved. Please try again.');
        });
    })

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

    getChallenges();

    function getChallenges() {
        $("#list").empty();
        $.get('CrossSiteScriptingStored/stored-xss', function (result, status) {
            for (var i = 0; i < result.length; i++) {
                var comment = $(html);
                comment.find('.user').text(result[i].user);
                comment.find('.time').text(result[i].dateTime);
                comment.find('p').text(result[i].text);
                $("#list").append(comment);
            }

        });
    }
})
