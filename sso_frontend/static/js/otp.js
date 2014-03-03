$(document).ready(function() {
 $("#id_otp").focus();
 $("#id_otp").on("input", function() {
  var otp = $(this).val();
  var parent = $(this).parent();
  var submit_icon = $("button[type=submit]").find("span");
  var len = $(this).data("len").split("-");
  if (otp.length >= parseInt(len[0]) && otp.length <= parseInt(len[1])) {
    parent.addClass("has-success has-feedback");
    parent.removeClass("has-warning");
    submit_icon.addClass("glyphicon-ok-circle").removeClass("glyphicon-remove-circle");
  } else {
    parent.addClass("has-warning has-feedback");
    parent.removeClass("has-success");
    submit_icon.addClass("glyphicon-remove-circle").removeClass("glyphicon-ok-circle");
  }
 });

});
