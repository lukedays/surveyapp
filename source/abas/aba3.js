if (Titanium.App.Properties.getString('servidor') == null) {
	a = Titanium.UI.createAlertDialog({
		title:'Aviso',
		message:'Especifique um servidor na aba Configurações.'
	});
	a.show();
}

var f = Titanium.Filesystem.getFile(Titanium.Filesystem.applicationDataDirectory, 'questionarios.json');
var arquivo = JSON.parse(f.read().text);
	
for (var u in arquivo.questionarios) {
		if (arquivo.questionarios[u]) {
	}
}

var v = u;

var download = Titanium.UI.createButton({
	title:'Receber do servidor',
    style:Titanium.UI.iPhone.SystemButtonStyle.BORDERED,
	color:'black',
	top:10,
	left:10,
	width:300,
	height:60
});

var upload = Titanium.UI.createButton({
	title:'Enviar para o servidor',
    style:Titanium.UI.iPhone.SystemButtonStyle.BORDERED,
	color:'black',
	top:100,
	left:10,
	width:300,
	height:60
});

function arquivos()
{
	var f = Titanium.Filesystem.getFile(Titanium.Filesystem.applicationDataDirectory, 'questionarios.json');
	var arquivo = JSON.parse(f.read().text);
	c = [];
	u = 0;
	for (var j in arquivo.questionarios) {
		if (arquivo.questionarios[j]) {
			nome = arquivo.questionarios[j][1];
			c[j] = Titanium.Network.createHTTPClient();
			c[j].onload = function()
			{
				Ti.App.Properties.setString(this.location, this.responseText);
				for (var j in arquivo.questionarios) {
					if (arquivo.questionarios[j]) {
						nome = arquivo.questionarios[j][1];
						f = Titanium.Filesystem.getFile(Titanium.Filesystem.applicationDataDirectory, nome);
						f.write(Ti.App.Properties.getString('http://' + Titanium.App.Properties.getString('servidor') + '/arquivos/' + nome));
					}
				}
				u++;
				if (u == v) {
					a = Titanium.UI.createAlertDialog({
						title:'Aviso',
						message:'Operação concluída!'
					});
					a.show();
				}
				//Ti.API.info(this.location);
			};
			c[j].open('GET','http://' + Titanium.App.Properties.getString('servidor') + '/arquivos/' + nome);
			c[j].send();
		}
	}
};

download.addEventListener('click', function(e)
{
	xhr = Titanium.Network.createHTTPClient();
	xhr.onload = function()
	{
		nome = 'questionarios.json';
		var f = Titanium.Filesystem.getFile(Titanium.Filesystem.applicationDataDirectory, nome);
		f.write(this.responseText);
		arquivos();
		//Ti.API.info(this.location);
	};
	xhr.open('GET', 'http://' + Titanium.App.Properties.getString('servidor') + '/arquivos/questionarios.json');
	xhr.send();
});

upload.addEventListener('click', function(e)
{
	var f = Titanium.Filesystem.getFile(Titanium.Filesystem.applicationDataDirectory, 'questionarios.json');
	var arquivo = JSON.parse(f.read().text);
	u = 0;
	for (var j in arquivo.questionarios) {
		if (arquivo.questionarios[j]) {
			nome = arquivo.questionarios[j][1];
			f = Titanium.Filesystem.getFile(Titanium.Filesystem.applicationDataDirectory, nome);
			var dados = f.read();
			var xhr = Titanium.Network.createHTTPClient();
			xhr.onload = function () {
				u++;
				if (u == v) {
					a = Titanium.UI.createAlertDialog({
						title:'Aviso',
						message:'Operação concluída!'
					});
					a.show();
				}
			};
			xhr.open('POST', 'http://' + Titanium.App.Properties.getString('servidor') + '/upload.php');	
			xhr.send({'arquivo':dados});
		}
	}
});

Titanium.UI.currentWindow.add(download);
Titanium.UI.currentWindow.add(upload);


