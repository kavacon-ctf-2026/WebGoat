function cleanup() {
	$.get('SpoofCookie/cleanup', function() {
		document.querySelectorAll('.spoof-auth-active').forEach(function(marker) { marker.remove(); });
		$('#spoof_username').removeAttr('disabled');
		$('#spoof_password').removeAttr('disabled');
		$('#spoof_submit').removeAttr('disabled');
		$('#spoof_attack_feedback').html('');
		$('#spoof_attack_output').html('');
	});
}
