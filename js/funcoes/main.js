// Orientações possíveis da tela
Titanium.UI.currentWindow.orientationModes = [
	Titanium.UI.PORTRAIT,
	Titanium.UI.LANDSCAPE_LEFT,
	Titanium.UI.LANDSCAPE_RIGHT
];

// u armazena o índice da última pergunta (começando do 0)
for (var u in arquivo.registros[0]) {
	if (arquivo.registros[0][u]) {
	}
}

// v armazena o índice da última pergunta (começando do 1)
var v = parseInt(u, 10) + 1;

// Montagem do formulário
var views = [];
var viewspicker = [];
var perguntas = [];
var tipos = [];
var labels = [];
var labelspicker = [];
var respostas = [];
var requeridas = [];
var alternativas = [];
var data = new Date();
var altura;
var valor;

for (var j in arquivo.registros[0]) {
	if (arquivo.registros[0][j]) {
		tipos[j] = arquivo.registros[0][j][2];
        requeridas[j] = arquivo.registros[0][j][5];
		if (tipos[j] == 5 || tipos[j] == 6) {
			views[j] = Titanium.UI.createView({
				backgroundColor:'black'
			});
			viewspicker[j] = Titanium.UI.createScrollView({
				backgroundColor:'black',
				contentWidth:'auto',
				contentHeight:'auto',
				showVerticalScrollIndicator:true,
				height:105,
				top:0
			});	
			perguntas[j] = Titanium.UI.createLabel({
				top:10,
				left:10,
				width:300,
				height:'auto',
				color:'white',
				font:{fontSize:16,fontFamily:'Helvetica Neue',fontWeight:'bold'},
				text:arquivo.registros[0][j][1]
			});
			if (tipos[j] == 6) {
				alternativas[j] = Titanium.UI.createLabel({
					top:15 + perguntas[j].height,
					left:10,
					width:300,
					height:'auto',
					color:'#99ccFF',
					font:{fontSize:16,fontFamily:'Helvetica Neue',fontWeight:'bold'}
				});
				viewspicker[j].add(alternativas[j]);
			}
			viewspicker[j].add(perguntas[j]);
			views[j].add(viewspicker[j]);
		}
		else {
			views[j] = Titanium.UI.createScrollView({
				backgroundColor:'black',
				contentWidth:'auto',
				contentHeight:'auto',
				showVerticalScrollIndicator:true
			});
			perguntas[j] = Titanium.UI.createLabel({
				top:10,
				left:10,
				width:300,
				height:'auto',
				color:'white',
				font:{fontSize:16,fontFamily:'Helvetica Neue',fontWeight:'bold'},
				text:arquivo.registros[0][j][1]
			});
			views[j].add(perguntas[j]);
		}
		
		// Vazio
		if (tipos[j] == 0) {
			arquivo.registros[x][j] = '';
			respostas[j] = Titanium.UI.createLabel({
				top:15 + perguntas[j].size.height,
				left:10,
				width:300,
				height:'auto',
				color:'white',
				font:{fontSize:16,fontFamily:'Helvetica Neue',fontWeight:'bold'},
				text:'',
				value:''
			});
		}
		
		// Texto
		else if (tipos[j] == 1) {
			if (arquivo.registros[x][j]) {
				valor = arquivo.registros[x][j];
			}
			else {
				arquivo.registros[x][j] = '';
				valor = arquivo.registros[x][j];
			}
			respostas[j] = Titanium.UI.createTextField({
				top:15 + perguntas[j].size.height,
				left:10,
				width:300,
				height:40,
				color:'black',
				value:valor,
				autocorrect:false,
				borderStyle:Titanium.UI.INPUT_BORDERSTYLE_ROUNDED
			});
		}
		
		// Texto longo
		else if (tipos[j] == 2) {
			if (arquivo.registros[x][j]) {
				valor = arquivo.registros[x][j];
			}
			else {
				arquivo.registros[x][j] = '';
				valor = arquivo.registros[x][j];
			}
			respostas[j] = Titanium.UI.createTextArea({
				top:15 + perguntas[j].size.height,
				left:10,
				width:300,
				height:150,
				color:'black',
				value:valor,
				autocorrect:false,
				borderWidth:3,
				borderColor:'white',
				borderRadius:5,
				font:{fontSize:15,fontFamily:'Helvetica Neue'}
			});
		}
		
		// Número
		else if (tipos[j] == 3) {
			if (arquivo.registros[x][j]) {
				valor = arquivo.registros[x][j];
			}
			else {
				arquivo.registros[x][j] = '';
				valor = arquivo.registros[x][j];
			}
			respostas[j] = Titanium.UI.createTextField({
				top:15 + perguntas[j].size.height,
				left:10,
				width:300,
				height:40,
				color:'black',
				value:valor,
				autocorrect:false,
				keyboardType:Titanium.UI.KEYBOARD_NUMBER_PAD,
				borderStyle:Titanium.UI.INPUT_BORDERSTYLE_ROUNDED
			});
		}
		
		// Switches
		else if (tipos[j] == 4) {
			respostas[j] = [];
			if (!arquivo.registros[x][j]) {
				arquivo.registros[x][j] = '';
			}
			altura = 25;
			for (var k in arquivo.registros[0][j][3]) {
				if (arquivo.registros[0][j][3][k]) {
					labels[k] = Titanium.UI.createLabel({
						top:perguntas[j].size.height + altura + 3,
						left:10,
						width:200,
						height:'auto',
						color:'white',
						font:{fontSize:15,fontFamily:'Helvetica Neue',fontWeight:'bold'},
						text:arquivo.registros[0][j][3][k]
					});
					if (arquivo.registros[x][j] != '') {
						if (arquivo.registros[x][j][k] == 1) {
							valor = true;
						}
						else {
							valor = false;
						}
					}
					else {
						valor = false;
					}
					respostas[j][k] = Titanium.UI.createSwitch({
						value:valor,
						top:perguntas[j].size.height + altura,
						right:5
					});
					altura += labels[k].size.height + 25;
				}
			}
		}
		
		// Data
		else if (tipos[j] == 5) {
			if (arquivo.registros[x][j]) {
				data.setDate(arquivo.registros[x][j][0]);
				data.setMonth(arquivo.registros[x][j][1] - 1);
				data.setFullYear(arquivo.registros[x][j][2]);
			}
			else {
				arquivo.registros[x][j] = '';
			}
			respostas[j] = Ti.UI.createPicker({
				type:Ti.UI.PICKER_TYPE_DATE,
				value:data,
				top:105,
				selectionIndicator:true
			});
			respostas[j].addEventListener('change', function(e) {});
		}
		
		// Picker
		else if (tipos[j] == 6) {
			if (arquivo.registros[x][j]) {
				valor = arquivo.registros[x][j];
			}
			else {
				arquivo.registros[x][j] = '';
				valor = 0;
			}
			respostas[j] = Ti.UI.createPicker({
				top:105,
                width:320,
				selectionIndicator:true
			});
			for (var k in arquivo.registros[0][j][3]) {
				if (arquivo.registros[0][j][3][k]) {
					labelspicker[k] = Titanium.UI.createPickerRow({
						title:arquivo.registros[0][j][3][k],
						index:k
					});
				}
			}
			respostas[j].add(labelspicker);
			respostas[j].setSelectedRow(0, valor, true);
			labelspicker = [];
			respostas[j].addEventListener('change', function (e) {
				var opcao = e.selectedValue[0];
				if (tipos[scrollableView.currentPage] == 6) {
					alternativas[scrollableView.currentPage].text = opcao;
				}
			});
		}
		
		// Exibição dos itens
		if (tipos[j] == 4) {
			for (var k in labels) {
				if (respostas[j][k]){
					views[j].add(labels[k]);
					views[j].add(respostas[j][k]);
				}
			}
		}
		else if (tipos[j] != 0) {
			views[j].add(respostas[j]);
		}
		labels = [];
	}
}

// Montagem da scrollableView, que dá suporte às views das perguntas
var scrollableView = Titanium.UI.createScrollableView({
	views:views,
    showPagingControl:false,
	maxZoomScale:1.0,
	currentPage:0
});
Titanium.UI.currentWindow.add(scrollableView);

// Ajuste do tamanho dos campos com a mudanca de orientação (vertical/horizontal) do dispositivo
/*
Ti.Gesture.addEventListener('orientationchange', function(e) {
	Ti.API.info(e);
	for (var j in respostas) {
		if (respostas[j]) {
			if (tipos[j] == 1 || tipos[j] == 2 || tipos[j] == 3) {
				if (e.orientation == 3 || e.orientation == 4 || e.orientation == Titanium.UI.LANDSCAPE_LEFT || e.orientation == Titanium.UI.LANDSCAPE_RIGHT) {
					respostas[j].width = 450;
				}
				else {
					respostas[j].width = 300;
				}
			}
		}
	}
});*/

var i = scrollableView.currentPage;

// Espaço vazio
var flexSpace = Titanium.UI.createButton({
	systemButton:Titanium.UI.iPhone.SystemButton.FLEXIBLE_SPACE
});

// Botão primeira pergunta
var primeira = Titanium.UI.createButton({
	title:'Primeira',
	style:Titanium.UI.iPhone.SystemButtonStyle.BORDERED
});
primeira.addEventListener('click', function(e)
{
	scrollableView.scrollToView(0);
});

// Botão última pergunta
var ultima = Titanium.UI.createButton({
	title:'Última',
	style:Titanium.UI.iPhone.SystemButtonStyle.BORDERED
});
ultima.addEventListener('click', function(e)
{
	scrollableView.scrollToView(u);
});

// Estado das questões
estado = [];
for (var k in arquivo.registros[0]) {
	if (arquivo.registros[0][k][4]) {
		estado[k] = 0;
	}
	else {
		estado[k] = 1;
	}
}

// Botão anterior
var anterior = Titanium.UI.createButton({
	title:'Anterior',
	style:Titanium.UI.iPhone.SystemButtonStyle.BORDERED
});
anterior.addEventListener('click', function(e)
{
	z = scrollableView.currentPage;
	inc_gravar(z);
	if (z != 0) {
		var jump = z - 1;
		while (estado[jump] == 0) {
			jump--;
		}
		scrollableView.scrollToView(jump);
	}
	else {
		Titanium.UI.currentWindow.close();
	}
});
	
// Botão próxima
var proxima = Titanium.UI.createButton({
	title:'Próxima',
	style:Titanium.UI.iPhone.SystemButtonStyle.BORDERED
});
proxima.addEventListener('click', function(e)
{
	z = scrollableView.currentPage;
	if ((tipos[z] == 1 || tipos[z] == 2 || tipos[z] == 3) && requeridas[z] == 1 && respostas[z].value == '') {
        a = Titanium.UI.createAlertDialog({
		title:'Aviso',
		message:'É obrigatório responder esta pergunta!'
        });
        a.show();
    }
    else {
		inc_gravar(z);
        if (z != u) {
			for (var k in arquivo.registros[0]) {
				if (arquivo.registros[0][k][4]) {
					var expressao = arquivo.registros[0][k][4];
					var cont = 0;
					for (var l in arquivo.registros[0]) {
						if (arquivo.registros[0][l]) {
							if (arquivo.registros[0][l][0] != "" && arquivo.registros[0][l][0] != null) {
								var numero = cont;
								var subst1 = "arquivo.registros[x][" + numero + "]=";
								expressao = expressao.replace(arquivo.registros[0][l][0] + "=", subst1);
								expressao = expressao.replace(arquivo.registros[0][l][0] + " =", subst1);
								var subst2 = "arquivo.registros[x][" + numero + "]!";
								expressao = expressao.replace(arquivo.registros[0][l][0] + "!", subst2);
								expressao = expressao.replace(arquivo.registros[0][l][0] + " !", subst1);
								var subst3 = "arquivo.registros[x][" + numero + "]>";
								expressao = expressao.replace(arquivo.registros[0][l][0] + ">", subst3);
								expressao = expressao.replace(arquivo.registros[0][l][0] + " >", subst1);
								var subst4 = "arquivo.registros[x][" + numero + "]<";
								expressao = expressao.replace(arquivo.registros[0][l][0] + "<", subst4);
								expressao = expressao.replace(arquivo.registros[0][l][0] + " <", subst1);
							}
							cont++;
						}
					}
					//Ti.API.info(arquivo.registros[0][k][4] + ">>>" + expressao);
					eval("if (" + expressao + ") { estado[k] = 1; } else { estado[k] = 0; }");
				}
			}
			
			var jump = z + 1;
			while (estado[jump] == 0) {
				jump++;
			}
			if (jump <= u) {
				scrollableView.scrollToView(jump);
			}
			else {
				scrollableView.scrollToView(u);
			}
        }
        else {
            Titanium.UI.currentWindow.close();
        }
    }
});

// Ir para questão específica
var irpara = Titanium.UI.createButton({
	title:'Ir para',
	style:Titanium.UI.iPhone.SystemButtonStyle.BORDERED
});
irpara.addEventListener('click', function()
{
	var t = Titanium.UI.create2DMatrix();
	t = t.scale(0);

	var win = Titanium.UI.createWindow({
		top:20,
		backgroundColor:'black',
		borderWidth:5,
		borderColor:'#999',
		height:200,
		width:300,
		borderRadius:10,
		opacity:0.92,
		transform:t
	});

	var t1 = Titanium.UI.create2DMatrix();
	t1 = t1.scale(1.1);
	var a = Titanium.UI.createAnimation();
	a.transform = t1;
	a.duration = 200;

	a.addEventListener('complete', function()
	{
		var t2 = Titanium.UI.create2DMatrix();
		t2 = t2.scale(1.0);
		win.animate({transform:t2, duration:200});
	});
	
	var titulo = Titanium.UI.createLabel({
		top:20,
		width:250,
		height:'auto',
		color:'white',
		font:{fontSize:16,fontFamily:'Helvetica Neue',fontWeight:'bold'},
		text:'Digite o número da questão para avançar:'
	});
	
	var questao = Titanium.UI.createTextField({
		top:70,
		width:250,
		height:40,
		color:'black',
		autocorrect:false,
		borderStyle:Titanium.UI.INPUT_BORDERSTYLE_ROUNDED,
		keyboardType:Titanium.UI.KEYBOARD_NUMBER_PAD
	});

	var b = Titanium.UI.createButton({
		title:'Avançar',
		color:'black',
		height:30,
		width:150,
		top:130
	});
	win.add(b);
	win.add(titulo);
	win.add(questao);
	b.addEventListener('click', function()
	{
		var ultima = u;
		ultima++;
		if (questao.value > 0 && questao.value <= ultima) {
			scrollableView.scrollToView(questao.value - 1);
		}
		var t3 = Titanium.UI.create2DMatrix();
		t3 = t3.scale(0);
		win.close({transform:t3,duration:300});
	});

	win.open(a);
});

// Número da página
var marcador = Ti.UI.createLabel({
		text:i + 1 + ' de ' + v,
		color:'white',
		font:{fontSize:17, fontWeight:'bold'}
});

// Navegação
scrollableView.addEventListener('scroll', function(e)
{
	inc_gravar(i);
	
	// Fechar teclado
	if (tipos[i] == 1 || tipos[i] == 2 || tipos[i] == 3) {
		respostas[i].blur();
	}
	
	i = scrollableView.currentPage;
	
	// Atualização do número da página
	marcador = Ti.UI.createLabel({
		text:i + 1 + ' de ' + v,
		color:'white',
		font:{fontSize:17, fontWeight:'bold'}
	});
	
	// Abrir teclado
	if (tipos[i] == 1 || tipos[i] == 2 || tipos[i] == 3) {
		respostas[i].focus();
	}
	
	// Correção para o picker
	if (tipos[i] == 6) {
		var opcao = arquivo.registros[0][i][3][parseInt(respostas[i].getSelectedRow(0).index, 10)];
		alternativas[i].text = opcao;
	}
	
	//Comentar a proxima linha quando utilizar o SDK antigo (Label em Toolbar nao suportada).
    Titanium.UI.currentWindow.setToolbar([primeira,flexSpace,marcador,flexSpace,irpara,ultima]);
	//Descomentar a proxima linha quando utilizar o SDK antigo.
    //Titanium.UI.currentWindow.setToolbar([primeira,flexSpace,ultima]);
});

Titanium.UI.currentWindow.leftNavButton = anterior;
Titanium.UI.currentWindow.rightNavButton = proxima;

//Comentar a proxima linha quando utilizar o SDK antigo (Label em Toolbar nao suportada).
Titanium.UI.currentWindow.setToolbar([primeira,flexSpace,marcador,flexSpace,irpara,ultima]);
//Descomentar a proxima linha quando utilizar o SDK antigo.
//Titanium.UI.currentWindow.setToolbar([primeira,flexSpace,ultima]);