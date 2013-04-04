var view = Titanium.UI.createScrollView({
	backgroundColor:'black',
	contentWidth:320,
	contentHeight:'auto',
	showVerticalScrollIndicator:true
});

var altura = 5;

//Titanium.App.Properties.setString('servidor', 'localhost:8888/site/iphone');
//Titanium.App.Properties.setString('servidor', 'servidoriphone.co.cc/jsmallfib_top');

if (Titanium.App.Properties.getString('servidor') == null) {
	value = 'Não especificado';
}
else {
	value = Titanium.App.Properties.getString('servidor');
}

var label1 = Titanium.UI.createLabel({
	top:10,
	left:10,
	width:300,
	height:'auto',
	color:'white',
	font:{fontSize:16,fontFamily:'Helvetica Neue',fontWeight:'bold'},
	text:'Servidor:'
});

altura += 10 + label1.size.height;

var textField1 = Titanium.UI.createTextField({
	top:altura,
	left:10,
	width:300,
	height:40,
	color:'black',
	value:value,
	autocorrect:false,
	borderStyle:Titanium.UI.INPUT_BORDERSTYLE_ROUNDED
});

altura += 10 + textField1.size.height;

textField1.addEventListener('return', function(e)
{
	Titanium.App.Properties.setString('servidor', e.value);
});

var label2 = Titanium.UI.createLabel({
	top:altura,
	left:10,
	width:300,
	height:'auto',
	color:'white',
	font:{fontSize:16,fontFamily:'Helvetica Neue',fontWeight:'bold'},
	text:'Número deste aparelho:'
});

altura += 5 + label2.size.height;

var textField2 = Titanium.UI.createTextField({
	top:altura,
	left:10,
	width:300,
	height:40,
	color:'black',
	autocorrect:false,
	borderStyle:Titanium.UI.INPUT_BORDERSTYLE_ROUNDED
});

altura += 10 + textField2.size.height;

textField2.addEventListener('return', function(e)
{
	Titanium.App.Properties.setString('aparelho', e.value);
});

var label3 = Titanium.UI.createLabel({
	left:10,
	top:altura,
	width:'auto',
	height:'auto',
	color:'white',
	font:{fontSize:16,fontFamily:'Helvetica Neue',fontWeight:'bold'},
	text:'Protótipo de aplicativo de pesquisa feito com o programa Titanium Mobile para iPhone. Versão 1.0'
});

view.add(label1);
view.add(label2);
view.add(label3);
view.add(textField1);
view.add(textField2);

Titanium.UI.currentWindow.add(view);


