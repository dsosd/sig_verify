function replace_newlines(str){
	return str.replace(/\n/g, "<br>");
}

function update_status(str, color){
	document.getElementById("drop_box").style.background=color;
	document.getElementById("status_text").innerHTML=replace_newlines(str);
}

function set_sha256(ev){
	var file=new FileReader();
	file.onloadend=function (){
		window.hash=sha256(file.result).toString();
		update_status("Drop sig file here", "#00b");
	};
	file.readAsArrayBuffer(ev.dataTransfer.files[0]);
}

function validate_sig(ev){
	var file=new FileReader();
	file.onloadend=function (){
		var file_raw=file.result;
		var data=JSON.parse(file_raw);
		var expiry=data["y"]+"-"+data["m"]+"-"+data["d"];

		var verifier=new JSEncrypt();
		verifier.setPublicKey(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwzQ83HnqX/L46Px5ixQR
W7QvPEHUJ5a0nLu3/WnaVCEkwg9wr6AHlx+EywGLIHsUbQteu3VxwUMLmD+o4yUC
8RKtSxaiLo9jAWgBjJqYf5zFrzdPwx9hv5ugXaoly70EWjK+cpiU61gS6lSGe3jz
6hLQiDdvJA1uDYOv63iHXIgFOy+NUWUekJoKZvFF1umsjYRd3knl/XIAZFmcGCIo
rufEcy4hTC3d3U9kIg8pWs9df0Il7ph0Um1Tkkgs7OsaOIbDJfmbbO1ZMgd+ZiRJ
qmXNthieCOQs5RzcxvkQfI0di2cj3Q095FfFI0Jf0kgxx07jrwLGbhCCUDIzDYfn
nt/jvaHfdb1O9rZnxmpO3JfJkWV0ZTaxbtMbg5OIKdiimoIKpnUSPGIwS2is3/5b
O/2CCaP1OB4nkWziNuPSubwDAh+D43IKpWBD0mrPWNO9b/zi406VTcaLPbrA+bLE
zb6cJSeGUfpbcMdS+xnqO7nNHsr/45eeXFAPSTPgK78VUHiEpVJLpKyFNHyPucaN
QJfLLaEoU5zGjv4Djb8cyuU1XEMT1NFocPQom5Fd2KbXwUKq9Zv7w+3V0w3SkNo7
S2deZjRpOhy3cJYVLm+XlAYu76UMJeYDNwKunjfCuypsXxJiHsz+rcC6YvAQLjCR
4jv8IjNM22KIE/afdy3aeecCAwEAAQ==
-----END PUBLIC KEY-----`);

		if (data["hash"]!=window.hash){
			update_status("FAIL\nHash mismatch", "#c00");
		}
		else if (verifier.verify(window.hash+":"+expiry+"\n", data["sig"], sha256)){
			var str="Validation\nSUCCESS"+"\n";
			str+=window.hash.substr(0, 32)+"\n";
			str+=window.hash.substr(32, 32)+"\n";
			str+=expiry;
			update_status(str, "#0c0");
		}
		else{
			update_status("Validation\nFAIL", "#c00");
		}
		document.getElementById("drop_box").onclick=function (ev){window.location.reload(); return false;};
	};
	file.readAsText(ev.dataTransfer.files[0]);
}

function kill_event(ev){
	ev.stopPropagation();
	ev.preventDefault();
	return false;
}

function drop_cb(ev){
	kill_event(ev);
	if (ev.dataTransfer.files.length){
		if (window.hash==undefined){
			set_sha256(ev);
		}
		else{
			validate_sig(ev);
		}
	}
}

//inline is better, but not permitted due to Mozilla AMO policy
document.addEventListener("DOMContentLoaded", function (){
		document.getElementById("drop_box").ondrop=function (ev){drop_cb(ev);};
		document.getElementById("drop_box").ondragover=function (ev){kill_event(ev);};
	}
);
