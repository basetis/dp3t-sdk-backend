
function submitLoginForm(){
	$("#login-form").submit();
}

function submitOTPGenerator(){
	var frm=$( "#otp-form" );
	var token=$("#auth-token").val();
	
	var request = $.ajax({
        url: frm.prop("action"),    
        method: frm.prop('method'), 
        headers: {
            'Authorization':token,
        }            
    });
	
	  request.done(function(response) {
		  $("#auth-token").val(response.token);
		  
		  var otpCode = response.otp.match(/\d{1,3}/g);
		  var otpToShow = otpCode[0].concat('.').concat(otpCode[1]).concat('.').concat(otpCode[2]).concat('.').concat(otpCode[3])
		  $("#otpCode").val(otpToShow);
      });

      request.fail(function(jqXHR, textStatus) {
    	  $("#auth-token").val(token);
      });
      
}