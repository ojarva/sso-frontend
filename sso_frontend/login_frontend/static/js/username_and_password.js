

$(document).ready(function () {
    var password_regex = new RegExp("^(.){8,}$");
    var username_regex = new RegExp("^(([\\w]{4,20})|([\\w.-]{4,}@[\\w.-]{4,}))$"); //"|([A-Za-z0-9_-\.]{4,}@[\w-\.]{4,})$");
    var otp_regex = new RegExp("^[0-9]{5,7}$");
    var emergency_regex = new RegExp("^[A-Za-z0-9]{20}$")
    var username_timeout, password_timeout;

    function username_error() {
        $("#id_username").next().addClass("glyphicon-remove");
        $("#id_username").parent().addClass("has-error");
    }
    function username_noerror() {
        clearTimeout(username_timeout);
        $("#id_username").next().removeClass("glyphicon-remove");
        $("#id_username").next().next().html("");
        $("#id_username").parent().removeClass("has-error");
    }
    function password_error() {
        $("#id_password").next().addClass("glyphicon-remove");
        $("#id_password").parent().addClass("has-error");
    }
    function password_noerror() {
        clearTimeout(password_timeout);
        $("#id_password").next().removeClass("glyphicon-remove");
        $("#id_password").next().next().html("");
        $("#id_password").parent().removeClass("has-error");
    }

    $("#id_username").keyup(function() {
        var username = $(this).val();
        var feedback = $(this).next();
        if (username.length == 0) {
            username_noerror();
        } else if (username.match(username_regex)) {
            username_noerror();
        } else {
            clearTimeout(username_timeout);
            username_timeout = setTimeout(username_error, 500);
            if (username.match(otp_regex)) {
                feedback.next().html("Please enter your username, not one-time code");
            }
        }
    });
    $("#id_password").keyup(function() {
        var password = $(this).val();
        var feedback = $(this).next();
        if (password.length == 0) {
            password_noerror();
        } else if (password.match(password_regex)) {
            if (password.replace(" ", "").match(emergency_regex)) {
                feedback.next().html("Please enter your password, not emergency code.");
                password_error();
            } else {
                password_noerror();
            }
        } else {
            clearTimeout(password_timeout);
            if (password.match(otp_regex)) {
                feedback.next().html("Please enter your password, not one-time code.");
                password_error();
            } else {
                feedback.next().html("");
                password_timeout = setTimeout(password_error, 500);
            }
        }
    });
});
