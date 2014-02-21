function refresh_admin_contents() {
 $.get("/ping/internal/admin_/indexview", function(data) {
  $("#admin_contents").html(data);
  setTimeout(refresh_admin_contents, 300000);
 });
};
$(document).ready(function() {
 setTimeout(refresh_admin_contents, 300000);
});
