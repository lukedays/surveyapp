var f = Titanium.Filesystem.getFile(Titanium.Filesystem.applicationDataDirectory, Titanium.App.Properties.getString('nome'));
var arquivo = JSON.parse(f.read().text);

var data = [];
for (var x in arquivo.registros) {
	if (arquivo.registros[x]) {
		var row = Ti.UI.createTableViewRow({
			title:'Registro ' + x,
			color:'white',
			hasChild:true,
			test:'../funcoes/existentes2.js',
			index:x
		});
		if (x != 0) {
			data[x] = row;
		}
	}
}

var tableView = Titanium.UI.createTableView({
	data:data,
	backgroundColor:'black'
});

tableView.addEventListener('click', function(e)
{
	win = Titanium.UI.createWindow({
		url:e.rowData.test,
		title:e.rowData.title,
		barColor:'black'
	});
	Titanium.App.Properties.setInt('x', e.rowData.index);
	Titanium.UI.currentTab.open(win,{animated:true});
});

var atualizar = Titanium.UI.createButton({
	title:'Atualizar',
	style:Titanium.UI.iPhone.SystemButtonStyle.BORDERED
});

atualizar.addEventListener('click', function(e)
{
	var f = Titanium.Filesystem.getFile(Titanium.Filesystem.applicationDataDirectory, Titanium.App.Properties.getString('nome'));
	var arquivo = JSON.parse(f.read().text);
	
	var data = [];
	for (var x in arquivo.registros) {
		if (arquivo.registros[x]) {
			var row = Ti.UI.createTableViewRow({
				title:'Registro ' + x,
				color:'white',
				hasChild:true,
				test:'../funcoes/existentes2.js',
				index:x
			});
			if (x != 0) {
				data[x] = row;
			}
		}
	}
	
	var tableView = Titanium.UI.createTableView({
		data:data,
		backgroundColor:'black'
	});
	
	tableView.addEventListener('click', function(e)
	{
		win = Titanium.UI.createWindow({
			url:e.rowData.test,
			title:e.rowData.title,
			barColor:'black'
		});
		Titanium.App.Properties.setInt('x', e.rowData.index);
		Titanium.UI.currentTab.open(win,{animated:true});
	});
	
	Titanium.UI.currentWindow.animate({view:tableView, transition:Ti.UI.iPhone.AnimationStyle.CURL_DOWN});
	Titanium.UI.currentWindow.setToolbar([atualizar]);
	Titanium.UI.currentWindow.add(tableView);
});

Titanium.UI.currentWindow.setToolbar([atualizar]);
Titanium.UI.currentWindow.add(tableView);