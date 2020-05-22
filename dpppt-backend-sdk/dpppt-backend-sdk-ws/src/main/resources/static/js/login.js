
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
		  $("#otpCode").val(response.otp);
      });

      request.fail(function(jqXHR, textStatus) {
    	  $("#auth-token").val(token);
      });
      
}

function submitPwdGenerator(){
	var frm=$( "#pwd-form" );
	var token=$("#auth-token").val();
	var psw=$("#psw").val();
	
	var request = $.ajax({
        url: frm.prop("action"),    
        method: frm.prop('method'), 
        headers: {
            'Authorization':token,
        },
        data: {password:psw},
        dataType: "json"
    });
	
	  request.done(function(response) {
		  $("#auth-token").val(response.token);
		  $("#pwdCode").val(response.password);
      });

      request.fail(function(jqXHR, textStatus) {
    	  $("#auth-token").val(token);
      });
      
}