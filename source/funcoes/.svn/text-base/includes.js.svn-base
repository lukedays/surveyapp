function inc_instalacao() {	
	if (Ti.App.Properties.getInt('instalacao') == null) {
		nome = 'questionarios.json';
		var dadosResources = Ti.Filesystem.getFile(Ti.Filesystem.resourcesDirectory, nome);
		var dadosDocuments = Ti.Filesystem.getFile(Ti.Filesystem.applicationDataDirectory, nome);
		dadosDocuments.write(dadosResources);
		 
		var f = Titanium.Filesystem.getFile(Titanium.Filesystem.applicationDataDirectory, nome);
		var instalacao = JSON.parse(f.read().text);
	
		for (var x in instalacao.questionarios) {
			if (instalacao.questionarios[x]) {
				nome = instalacao.questionarios[x][1];
				dadosResources = Ti.Filesystem.getFile(Ti.Filesystem.resourcesDirectory, nome);
				dadosDocuments = Ti.Filesystem.getFile(Ti.Filesystem.applicationDataDirectory, nome);
				dadosDocuments.write(dadosResources);
			}
		}
		Ti.App.Properties.setInt('instalacao', 1);
	}
}

function inc_abrir(test) {
	var f = Titanium.Filesystem.getFile(Titanium.Filesystem.applicationDataDirectory, 'questionarios.json');
	var arquivo = JSON.parse(f.read().text);
	
	var data = [];
	for (var j in arquivo.questionarios) {
		if (arquivo.questionarios[j]) {
			var row = Ti.UI.createTableViewRow({
				title:arquivo.questionarios[j][0],
				color:'white',
				hasChild:true,
				test:test,
				nome:arquivo.questionarios[j][1]
			});
			data[j] = row;
		}
	}
	
	tableView = Titanium.UI.createTableView({
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
		Titanium.App.Properties.setString('nome', e.rowData.nome);
		Titanium.UI.currentTab.open(win, {animated:true});
	});
}

function inc_gravar(z) {
	if (tipos[z] == 4) {
		arquivo.registros[x][z] = [];
		for (var k in respostas[z]) {
			if (respostas[z][k]) {
				if (respostas[z][k].value == true) {
					arquivo.registros[x][z][k] = 1;
				}
				else {
					arquivo.registros[x][z][k] = 0;
				}
			}
		}
	}
	else if (tipos[z] == 5) {
		arquivo.registros[x][z] = [];
		arquivo.registros[x][z][0] = respostas[z].value.getDate();
		arquivo.registros[x][z][1] = respostas[z].value.getMonth() + 1;
		arquivo.registros[x][z][2] = respostas[z].value.getFullYear();
	}
	else if (tipos[z] == 6) {
		arquivo.registros[x][z] = parseInt(respostas[z].getSelectedRow(0).index, 10);
	}
	else {
		arquivo.registros[x][z] = respostas[z].value;
	}
	f.write(JSON.stringify(arquivo));
}
	