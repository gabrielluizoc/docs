Autenticação
class AuthComponent( ComponentCollection $ collection , array $ config = [] )
Identificar, autenticar e autorizar usuários é uma parte comum de quase todos os aplicativos da web. No CakePHP, o AuthComponent fornece uma maneira conectável de executar essas tarefas. O AuthComponent permite combinar objetos de autenticação e autorização para criar maneiras flexíveis de identificar e verificar a autorização do usuário.

Sugestões de leitura antes de continuar
A configuração da autenticação requer várias etapas, incluindo a definição de uma tabela de usuários, a criação de um modelo, um controlador e visualizações, etc.

Isso tudo é coberto passo a passo no Tutorial do CMS .

Se você está procurando por soluções existentes de autenticação e / ou autorização para o CakePHP, dê uma olhada na seção Autenticação e Autorização da lista Awesome CakePHP.

Autenticação
Autenticação é o processo de identificar usuários pelas credenciais fornecidas e garantir que os usuários sejam quem eles dizem ser. Geralmente, isso é feito por meio de um nome de usuário e senha, que são verificados em relação a uma lista conhecida de usuários. No CakePHP, existem várias maneiras internas de autenticar usuários armazenados em seu aplicativo.

FormAuthenticatepermite autenticar usuários com base em dados POST de formulário. Geralmente, esse é um formulário de login no qual os usuários inserem informações.
BasicAuthenticate permite autenticar usuários usando a autenticação básica HTTP.
DigestAuthenticate permite autenticar usuários usando a autenticação Digest HTTP.
Por padrão, AuthComponentusa FormAuthenticate.

Escolhendo um tipo de autenticação
Geralmente, você desejará oferecer uma autenticação baseada em formulário. É o mais fácil para os usuários que usam um navegador da Web para usar. Se você estiver criando uma API ou um serviço da web, poderá considerar a autenticação básica ou a autenticação digest. As principais diferenças entre o resumo e a autenticação básica estão relacionadas principalmente à maneira como as senhas são tratadas. Na autenticação básica, o nome de usuário e a senha são transmitidos como texto simples para o servidor. Isso torna a autenticação básica inadequada para aplicativos sem SSL, pois você acabaria expondo senhas confidenciais. A autenticação Digest usa um hash de digitação do nome de usuário, senha e alguns outros detalhes. Isso torna a autenticação digest mais apropriada para aplicativos sem criptografia SSL.

Você também pode usar sistemas de autenticação como o OpenID; no entanto, o OpenID não faz parte do núcleo do CakePHP.

Configurando manipuladores de autenticação
Você configura os manipuladores de autenticação usando a authenticateconfiguração. Você pode configurar um ou muitos manipuladores para autenticação. O uso de vários manipuladores permite que você ofereça suporte a diferentes formas de registro de usuários. Ao registrar usuários, os manipuladores de autenticação são verificados na ordem em que são declarados. Uma vez que um manipulador é capaz de identificar o usuário, nenhum outro manipulador será verificado. Por outro lado, você pode interromper toda a autenticação lançando uma exceção. Você precisará capturar quaisquer exceções lançadas e manipulá-las conforme necessário.

Você pode configurar manipuladores de autenticação no seu controlador beforeFilter()ou initialize()métodos. Você pode passar informações de configuração para cada objeto de autenticação usando uma matriz:

// Configuração simples 
$ this -> Auth -> config ( 'authenticate' ,  [ 'Form' ]);

// Passa configurações em 
$ this -> Auth -> config ( 'authenticate' ,  [ 
    'Basic'  =>  [ 'userModel'  =>  'Members' ], 
    'Form'  =>  [ 'userModel'  =>  'Members' ] 
]);
No segundo exemplo, você notará que tivemos que declarar a userModelchave duas vezes. Para ajudá-lo a manter seu código DRY, você pode usar a allchave. Essa chave especial permite definir configurações que são passadas para todos os objetos conectados. A allchave também é exposta como AuthComponent::ALL:

// Passe as configurações usando 'all' 
$ this -> Auth -> config ( 'authenticate' ,  [ 
    AuthComponent :: ALL  =>  [ 'userModel'  =>  'Membros' ], 
    'Básico' , 
    'Formulário' 
]);
No exemplo acima, tanto Forme Basicvai ter as configurações definidas para a chave 'all'. Todas as configurações passadas para um objeto de autenticação específico substituirão a chave correspondente na chave "todos". Os principais objetos de autenticação suportam as seguintes chaves de configuração.

fieldsOs campos a serem usados ​​para identificar um usuário por. Você pode usar chaves usernamee passwordespecificar seus campos de nome de usuário e senha, respectivamente.
userModelO nome do modelo da tabela de usuários; o padrão é Usuários.
finderO método localizador a ser usado para buscar um registro do usuário. O padrão é 'all'.
passwordHasherClasse hasher de senha; Padrões para Default.
As opções scopee containforam obsoletas a partir de 3.1. Use um localizador personalizado para modificar a consulta para buscar um registro do usuário.
A userFieldsopção foi descontinuada a partir de 3.1. Use select()no seu localizador personalizado.
Para configurar campos diferentes para o usuário em seu initialize()método:

public  function  initialize () 
{ 
    parent :: initialize (); 
    $ this- > loadComponent ( 'Auth' ,  [ 
        'authenticate'  =>  [ 
            'Formulário'  =>  [ 
                'campos'  =>  [ 'username'  =>  'email' ,  'password'  =>  'passwd' ] 
            ] 
        ] 
    ] ); 
}
Não coloque outras Authchaves de configuração, tais como authError, loginAction, etc., dentro do authenticateou Formelemento. Eles devem estar no mesmo nível da chave de autenticação. A configuração acima com outra configuração do Auth deve se parecer com:

public  function  initialize () 
{ 
    parent :: initialize (); 
    $ this- > loadComponent ( 'Auth' ,  [ 
        'loginAction'  =>  [ 
            'controller'  =>  'Usuários' , 
            'action'  =>  'login' , 
            'plugin'  =>  'Usuários' 
        ], 
        'authError'  =>  'Você realmente acha que tem permissão para ver isso?' , 
        'Autenticar'  =>  [ 
            'Formulário'  =>  [ 
                '   =>  'email' ] 
            ] 
        ], 
        'armazenamento'  =>  'Sessão' 
    ]); 
}
Além da configuração comum, a autenticação básica suporta as seguintes chaves:

realmO reino sendo autenticado. Padrões para env('SERVER_NAME').
Além da configuração comum, a autenticação Digest suporta as seguintes chaves:

realmA autenticação do território é para. Padrões para o nome do servidor.
nonceUm nonce usado para autenticação. Padrões para uniqid().
qopPadrões para auth; Nenhum outro valor é suportado neste momento.
opaqueUma string que deve ser retornada inalterada pelos clientes. Padrões para md5($config['realm']).
Para encontrar o registro do usuário, o banco de dados é consultado apenas usando o nome de usuário. A verificação da senha é feita no PHP. Isso é necessário porque algoritmos hash como bcrypt (que é usado por padrão) geram um novo hash a cada vez, mesmo para a mesma string e você não pode fazer apenas uma comparação de string simples no SQL para verificar se a senha corresponde.

Customizando Consulta de Pesquisa
Você pode personalizar a consulta usada para buscar o registro do usuário usando a finder opção em authenticate class config:

public  function  initialize () 
{ 
    parent :: initialize (); 
    $ this- > loadComponent ( 'Auth' ,  [ 
        'authenticate'  =>  [ 
            'Formulário'  =>  [ 
                'finder'  =>  'auth' 
            ] 
        ], 
    ]); 
}
Isso exigirá que você UsersTabletenha o método do localizador findAuth(). No exemplo mostrado abaixo, a consulta é modificada para buscar apenas os campos obrigatórios e adicionar uma condição. Você deve garantir que você selecione os campos necessários para autenticar um usuário, como usernamee password:

 função  pública findAuth ( \ Cake \ ORM \ Consulta  $ query ,  array  $ options ) 
{ 
    $ query 
        -> select ([ 'id' ,  'nome de usuário' ,  'senha' ]) 
        -> onde ([ 'Users.active'  =>  1 ]);

    return  $ query ; 
}
finderopção está disponível desde 3.1. Antes disso, você pode usar scope e containopções para modificar uma consulta.

Identificando usuários e registrando-os
AuthComponent::identify( )
Você precisa ligar manualmente $this->Auth->identify()para identificar o usuário usando as credenciais fornecidas na solicitação. Em seguida, use $this->Auth->setUser() para registrar o usuário, ou seja, salvar as informações do usuário para a sessão.

Ao autenticar usuários, os objetos de autenticação anexados são verificados na ordem em que estão conectados. Quando um dos objetos puder identificar o usuário, nenhum outro objeto será verificado. Uma função de login de amostra para trabalhar com um formulário de login pode ser semelhante a:

 login de função  pública () { if ( $ this -> request -> é ( 'post' )) { $ user = $ this -> Auth -> identificador (); if ( $ user ) { $ this -> Auth -> setUser ( usuário $ ); retorne $ this -> redirect ( $ this -> Auth -> redirectUrl ()); } else { $ this

      
          
          
            
             
          
            -> Flash -> erro ( __ ( 'Nome de usuário ou senha incorretos' )); 
        } 
    } 
}
O código acima tentará primeiro identificar um usuário usando os dados POST. Se tiver êxito, definimos as informações do usuário para a sessão, de modo que ela persista entre as solicitações e, em seguida, redirecione para a última página visitada ou para uma URL especificada na loginRedirectconfiguração. Se o login não for bem-sucedido, uma mensagem flash será definida.

$this->Auth->setUser($data)registrará o usuário com quaisquer dados que forem passados ​​para o método. Na verdade, ele não verificará as credenciais em uma classe de autenticação.

Redirecionando Usuários Após o Login
AuthComponent::redirectUrl( )
Depois de registrar um usuário, geralmente você vai querer redirecioná-lo de volta para onde ele veio. Passe um URL para definir o destino para o qual o usuário deve ser redirecionado após o login.

Se nenhum parâmetro for passado, o URL retornado usará as seguintes regras:

Retorna o URL normalizado do redirectvalor da string de consulta, se estiver presente, e para o mesmo domínio em que o aplicativo atual está sendo executado. Antes de 3.4.0, o Auth.redirectvalor da sessão foi usado.
Se não houver um valor de string / sessão de consulta e houver uma configuração com loginRedirect, o loginRedirectvalor será retornado.
Se não houver nenhum valor de redirecionamento e não loginRedirect, /será retornado.
Criando sistemas de autenticação sem estado
Básico e digest são esquemas de autenticação sem estado e não requerem um POST ou um formulário inicial. Se estiver usando apenas autenticadores básicos / digest, você não precisará de uma ação de login no seu controlador. A autenticação sem estado irá rever as credenciais do usuário em cada solicitação, o que cria uma pequena quantidade de sobrecarga adicional, mas permite que os clientes façam login sem usar cookies e torna o AuthComponent mais adequado para criar APIs.

Para autenticadores sem estado, a storageconfiguração deve ser definida para Memory que o AuthComponent não use uma sessão para armazenar o registro do usuário. Você também pode querer definir config unauthorizedRedirectpara falseque AuthComponent lance um em ForbiddenExceptionvez do comportamento padrão de redirecionar para referenciador.

A unauthorizedRedirectopção só se aplica a usuários autenticados. Quando um usuário ainda não está autenticado e você não deseja que o usuário seja redirecionado, você precisará carregar um ou mais autenticantes sem estado, como Basicou Digest.

Objetos de autenticação podem implementar um getUser()método que pode ser usado para suportar sistemas de login de usuários que não dependem de cookies. Um método getUser típico examina a solicitação / ambiente e usa as informações para confirmar a identidade do usuário. Autenticação básica HTTP, por exemplo, usa $_SERVER['PHP_AUTH_USER']e $_SERVER['PHP_AUTH_PW']para os campos de nome de usuário e senha.

Caso a autenticação não funcione como esperado, verifique se as consultas são executadas (veja BaseAuthenticate::_query($username)). Caso nenhuma consulta seja executada, verifique se $_SERVER['PHP_AUTH_USER'] e $_SERVER['PHP_AUTH_PW']é preenchida pelo servidor web. Se você estiver usando o Apache com FastCGI-PHP, você pode precisar adicionar esta linha ao seu arquivo .htaccess no webroot:

RewriteRule  . *  -  [ E = HTTP_AUTHORIZATION :% { HTTP : Autorização }, L ]
Em cada solicitação, esses valores PHP_AUTH_USERe PHP_AUTH_PWsão usados ​​para re-identificar o usuário e garantir que ele seja o usuário válido. Tal como acontece com o authenticate()método do objeto de autenticação , o getUser()método deve retornar uma matriz de informações do usuário sobre o sucesso ou falsea falha.

 função  pública getUser ( ServerRequest  $ request ) 
{ 
    $ username  =  env ( 'PHP_AUTH_USER' ); 
    $ pass  =  env ( 'PHP_AUTH_PW' );

    if  ( vazio ( $ username )  ||  empty ( $ pass ))  { 
        retorno  falso ; 
    } 
    return  $ this -> _findUser ( $ username ,  $ pass ); 
}
A descrição acima é como você poderia implementar o método getUser para autenticação básica HTTP. O _findUser()método faz parte BaseAuthenticate e identifica um usuário com base em um nome de usuário e senha.

Usando a autenticação básica
A autenticação básica permite criar uma autenticação sem estado que pode ser usada em aplicativos de intranet ou em cenários de API simples. Credenciais de autenticação básica serão verificadas novamente em cada solicitação.

Autenticação básica transmite credenciais em texto sem formatação. Você deve usar HTTPS ao usar a autenticação básica.

Para usar a autenticação básica, você precisará configurar o AuthComponent:

$ this- > loadComponent ( 'Auth' ,  [ 
    'authenticate'  =>  [ 
        'Basic'  =>  [ 
            'campos'  =>  [ 'username'  =>  'username' ,  'password'  =>  'api_key' ], 
            'userModel '  =>  ' Usuários ' 
        ], 
    ] 
    ' armazenamento '  =>  ' Memória ' , 
    ' desautorizadoRedirect '  =>  falso 
]);
Aqui estamos usando o nome de usuário + chave de API como nossos campos e usamos o modelo de usuários.

Criando Chaves de API para Autenticação Básica
Como o HTTP básico envia credenciais em texto simples, não é aconselhável que os usuários enviem sua senha de login. Em vez disso, uma chave de API opaca é geralmente usada. Você pode gerar esses tokens de API aleatoriamente usando bibliotecas do CakePHP:

namespace  App \ Modelo \ Tabela ;

use  Cake \ Auth \ DefaultPasswordHasher ; 
use  Cake \ Utility \ Text ; 
use  Cake \ Event \ Event ; 
use  Cake \ ORM \ Table ; 
use  Cake \ Utility \ Security ;

A classe  UsersTable  estende a  tabela 
{ 
    public  function  beforeSave ( evento  $ event ) 
    { 
        $ entity  =  $ event -> getData ( 'entity' );

        if  ( $ entity -> isNew ())  { 
            $ hasher  =  novo  DefaultPasswordHasher ();

            // Gerar uma API 'token' 
            $ entity -> api_key_plain  =  Segurança :: hash ( Security :: randomBytes ( 32 ),  'sha256' ,  false );

            // Bcrypt o token para que BasicAuthenticate possa verificar 
            // durante o login. 
            $ entity -> api_key  =  $ hasher -> hash ( $ entidade -> api_key_plain ); 
        } 
        return  true ; 
    } 
}
O acima gera um hash aleatório para cada usuário enquanto eles são salvos. O código acima assume que você tem duas colunas api_key- para armazenar a chave da API em hash e api_key_plain- para a versão de texto sem formatação da chave da API, para que possamos exibi-la posteriormente para o usuário. Usar uma chave em vez de uma senha significa que, mesmo sobre HTTP simples, seus usuários podem usar um token opaco em vez de sua senha original. Também é aconselhável incluir lógica para permitir que as chaves de API sejam regeneradas a pedido do usuário.

Usando a Autenticação Digest
A autenticação Digest oferece um modelo de segurança aprimorado em relação à autenticação básica, pois as credenciais do usuário nunca são enviadas no cabeçalho da solicitação. Em vez disso, um hash é enviado.

Para usar a autenticação digest, você precisará configurar AuthComponent:

$ this- > loadComponent ( 'Auth' ,  [ 
    'authenticate'  =>  [ 
        'Digest'  =>  [ 
            'campos'  =>  [ 'username'  =>  'username' ,  'password'  =>  'digest_hash' ], 
            'userModel '  =>  ' Usuários ' 
        ], 
    ] 
    ' armazenamento '  =>  ' Memória ' , 
    ' desautorizadoRedirect '  =>  falso 
]);
Aqui estamos usando username + digest_hash como nossos campos e usamos o modelo Users.

Hashing senhas para autenticação Digest
Como a autenticação Digest requer uma senha com hash no formato definido pelo RFC, para codificar corretamente uma senha para uso com a autenticação Digest, você deve usar a função de hashing de senha especial em DigestAuthenticate. Se você estiver combinando autenticação digest com outras estratégias de autenticação, também é recomendável armazenar a senha de compilação em uma coluna separada, a partir do hash de senha normal:

namespace  App \ Modelo \ Tabela ;

use  Cake \ Auth \ DigestAuthenticate ; 
use  Cake \ Event \ Event ; 
use  Cake \ ORM \ Table ;

A classe  UsersTable  estende a  tabela 
{ 
    public  function  beforeSave ( evento  $ event ) 
    { 
        $ entity  =  $ event -> getData ( 'entity' );

        // Crie uma senha para a autenticação de resumo. 
        $ entity- > digest_hash  =  DigestAuthenticate :: password ( 
            $ entidade -> username , 
            $ entidade -> plain_password , 
            env ( 'SERVER_NAME' ) 
        ); 
        retorno  verdadeiro ; 
    } 
}
As senhas para autenticação digest precisam de um pouco mais de informação do que outros hashes de senha, com base na RFC para autenticação Digest.

O terceiro parâmetro de DigestAuthenticate::password()deve corresponder ao valor de configuração 'realm' definido quando DigestAuthentication foi configurado em AuthComponent::$authenticate. Este padrão é env('SCRIPT_NAME'). Você pode querer usar uma string estática se quiser hashes consistentes em vários ambientes.

Criando Objetos de Autenticação Customizados
Como os objetos de autenticação são conectáveis, você pode criar objetos de autenticação personalizados em seu aplicativo ou plug-ins. Se, por exemplo, você quisesse criar um objeto de autenticação OpenID. Em src / Auth / OpenidAuthenticate.php você pode colocar o seguinte:

namespace  App \ Auth ;

use  Cake \ Auth \ BaseAuthenticate ; 
use  Cake \ Http \ ServerRequest ; 
use  Cake \ Http \ Response ;

A classe  OpenIDAuthenticate  estende  BaseAuthenticate 
{ 
    public  function  authenticate ( solicitação $ ServerRequest  , Response $ response ) { // Faz coisas para OpenID aqui. // Retorna uma matriz de usuários se eles puderem autenticar o usuário, // retornar false se não. } }  
    
        
        
        
    

Os objetos de autenticação devem retornar falsese não puderem identificar o usuário e uma matriz de informações do usuário, se puderem. Não é necessário estender BaseAuthenticateapenas o seu objeto de autenticação Cake\Event\EventListenerInterface. A BaseAuthenticateclasse fornece vários métodos úteis que são comumente usados. Você também pode implementar um getUser()método se o seu objeto de autenticação precisar suportar autenticação sem estado ou sem cookie. Veja as seções sobre autenticação básica e digest abaixo para mais informações.

AuthComponentaciona dois eventos Auth.afterIdentifye Auth.logout, após um usuário ter sido identificado e antes de um usuário ser desconectado, respectivamente. Você pode definir funções de retorno de chamada para esses eventos, retornando uma matriz de mapeamento do implementedEvents()método de sua classe de autenticação:

 Função  pública implementedEvents () 
{ 
    return  [ 
        'Auth.afterIdentify'  =>  'afterIdentify' , 
        'Auth.logout'  =>  'logout' 
    ]; 
}
Usando objetos de autenticação personalizados
Depois de criar seus objetos de autenticação personalizados, você poderá usá-los incluindo-os na AuthComponentmatriz de autenticação:

$ this -> Auth -> config ( 'autenticar' ,  [ 
    'Openid' ,  // objeto de autenticação do aplicativo. 
    'AuthBag.Openid' ,  // objeto de autenticação do plugin. 
]);
Observe que, ao usar a notação simples, não há palavra 'Authenticate' ao iniciar o objeto de autenticação. Em vez disso, se você usar namespaces, precisará definir o namespace completo da classe, incluindo a palavra 'Authenticate'.

Manipulando Solicitações Não Autenticadas
Quando um usuário não autenticado tenta acessar uma página protegida primeiro, o unauthenticated()método do último autenticador na cadeia é chamado. O objeto autenticado pode manipular o envio de resposta ou redirecionamento retornando um objeto de resposta para indicar que nenhuma ação adicional é necessária. Devido a isso, a ordem na qual você especifica o provedor de autenticação em authenticate questões de configuração.

Se o autenticador retornar null, AuthComponentredirecionará o usuário para a ação de login. Se for um pedido AJAX e config ajaxLoginfor especificado que o elemento é renderizado, outro código de status HTTP 403 será retornado.

Exibindo mensagens relacionadas ao Auth Auth
Para exibir as mensagens de erro da sessão geradas pelo Auth, você precisa adicionar o seguinte código ao seu layout. Adicione as duas linhas seguintes ao arquivo src / Template / Layout / default.ctp na seção do corpo:

// Somente isto é necessário após 3.4.0 
echo  $ this -> Flash -> render ();

// Antes de 3.4.0, isso também será necessário. 
echo  $ this -> Flash -> render ( 'auth' );
Você pode personalizar as mensagens de erro e as configurações de flash AuthComponent . Usando flashconfig você pode configurar os parâmetros AuthComponentusados ​​para configurar mensagens flash. As teclas disponíveis são

key- A chave para usar, o padrão é "padrão". Antes de 3.4.0, a chave padrão era 'auth'.
element - O nome do elemento a ser usado para renderização, o padrão é nulo.
params- A matriz de parâmetros adicionais a serem usados ​​é padronizada [].
Além das configurações de mensagem flash, você pode personalizar outros AuthComponentusos de mensagens de erro . Nas beforeFilter()configurações do seu controlador ou componente, você pode usar authErrorpara personalizar o erro usado quando a autorização falha:

$ this -> Auth -> config ( 'authError' ,  "Woopsie, você não está autorizado a acessar esta área." );
Às vezes, você deseja exibir o erro de autorização somente depois que o usuário já tiver efetuado login. Você pode suprimir essa mensagem definindo seu valor como booleano false.

Nas beforeFilter()configurações do seu controlador ou componente:

if  ( ! $ this -> Auth -> usuário ())  { 
    $ this -> Auth -> config ( 'authError' ,  false ); 
}
Hashing Passwords
Você é responsável pelo hashing das senhas antes que elas sejam mantidas no banco de dados, a maneira mais fácil é usar uma função setter na sua entidade User:

namespace  App \ Model \ Entity ;

use  Cake \ Auth \ DefaultPasswordHasher ; 
use  Cake \ ORM \ Entity ;

classe  User  estende a  entidade 
{

    // ...

     função  protegida _setPassword ( $ password ) 
    { 
        if  ( strlen ( $ password )  >  0 )  { 
          return  ( novo  DefaultPasswordHasher ) -> hash ( $ password ); 
        } 
    }

    // ... 
}
AuthComponenté configurado por padrão para usar DefaultPasswordHasher ao validar as credenciais do usuário, portanto, nenhuma configuração adicional é necessária para autenticar os usuários.

DefaultPasswordHasherusa o algoritmo de hashing bcrypt internamente, que é uma das soluções de hashing de senhas mais fortes usadas na indústria. Embora seja recomendável usar essa classe hasher de senha, o caso pode ser que você esteja gerenciando um banco de dados de usuários cuja senha foi codificada de forma diferente.

Criando Classes Hasher de Senha Customizada
Para usar um hasher de senha diferente, você precisa criar a classe em src / Auth / LegacyPasswordHasher.php e implementar os métodos hash()e check(). Esta classe precisa estender a AbstractPasswordHasherclasse:

namespace  App \ Auth ;

use  Cake \ Auth \ AbstractPasswordHasher ;

classe  LegacyPasswordHasher  estende  AbstractPasswordHasher 
{

     função  pública hash ( $ password ) 
    { 
        return  sha1 ( $ password ); 
    }

     verificação de função  pública ( $ password , $ hashedPassword ) { return sha1 ( $ password ) === $ hashedPassword ; } } 
    
           
    

Então você é obrigado a configurar o AuthComponentpara usar sua própria senha hasher:

public  function  initialize () 
{ 
    parent :: initialize (); 
    $ this- > loadComponent ( 'Auth' ,  [ 
        'authenticate'  =>  [ 
            'Formulário'  =>  [ 
                'passwordHasher'  =>  [ 
                    'className'  =>  'Legado' , 
                ] 
            ] 
        ] 
    ]); 
}
O suporte a sistemas legados é uma boa ideia, mas é ainda melhor manter seu banco de dados com os mais recentes avanços de segurança. A seção a seguir explicará como migrar de um algoritmo de hash para o padrão do CakePHP.

Alterando Algoritmos de Hashing
O CakePHP fornece uma maneira limpa de migrar as senhas de seus usuários de um algoritmo para outro. Isso é obtido através da FallbackPasswordHasherclasse. Supondo que você está migrando seu aplicativo do CakePHP 2.x que usa sha1hashes de senha, você pode configurar da AuthComponentseguinte maneira:

public  function  initialize () 
{ 
    parent :: initialize (); 
    $ this- > loadComponent ( 'Auth' ,  [ 
        'authenticate'  =>  [ 
            'Formulário'  =>  [ 
                'passwordHasher'  =>  [ 
                    'className'  =>  'Fallback' , 
                    'hashers'  =>  [ 
                        'Padrão' , 
                        'Fraco '  =>  [ ' hashType '  =>  ' sha1 ' ] 
                    ] 
                ] 
            ] 
        ] 
    ]);

O primeiro nome que aparece na hasherschave indica qual das classes é a preferida, mas fará fallback para os outros na lista se a verificação não for bem sucedida.

Ao usar o, WeakPasswordHashervocê precisará definir Security.salto valor para garantir que as senhas sejam salgadas.

Para atualizar as senhas dos usuários antigos em tempo real, você pode alterar a função de login de acordo:

 login de função  pública () { if ( $ this -> request -> é ( 'post' )) { $ user = $ this -> Auth -> identificador (); if ( $ user ) { $ this -> Auth -> setUser ( usuário $ ); if ( $ this -> Auth -> authenticationProvider () -> needsPasswordRehash ()) { $ usuário =

      
          
          
            
              
                  $ this -> Usuários -> get ( $ this -> Auth -> user ( 'id' )); 
                $ user -> password  =  $ this -> request -> getData ( 'password' ); 
                $ this -> Usuários -> save ( $ user ); 
            } 
            retornar  $ this -> redirect ( $ this -> Auth -> redirectUrl ()); 
        } 
        ... 
    } 
}
Como você pode ver, estamos apenas definindo a senha simples novamente para que a função setter na entidade altere a senha como mostrado no exemplo anterior e salve a entidade.

Registrando manualmente usuários em
AuthComponent::setUser( usuário $ array )
Às vezes, surge a necessidade de registrar manualmente um usuário, por exemplo, logo após o registro no aplicativo. Você pode fazer isso chamando $this->Auth->setUser()com os dados do usuário que você deseja 'login':

public  function  register () 
{ 
    $ usuário  =  $ this -> Usuários -> newEntity ( $ this -> request -> getData ()); 
    if  ( $ this -> Usuários -> save ( $ user ))  { 
        $ this -> Auth -> setUser ( $ usuário -> toArray ()); 
        retornar  $ this -> redirect ([ 
            'controller'  =>  'Usuários' , 
            'ação' =>  'casa' 
        ]]; 
    } 
}
Certifique-se de adicionar manualmente o novo ID do usuário ao array passado para o setUser() método. Caso contrário, você não terá o ID do usuário disponível.

Acessando o usuário conectado
AuthComponent::user( $ key = null )
Uma vez que o usuário esteja logado, você precisará de algumas informações específicas sobre o usuário atual. Você pode acessar o usuário conectado no momento usando AuthComponent::user():

// De dentro de um controlador ou outro componente. 
$ this -> Auth -> user ( 'id' );
Se o usuário atual não estiver logado ou a chave não existir, será retornado nulo.

Registrando Usuários Fora
AuthComponent::logout( )
Eventualmente, você vai querer uma maneira rápida de autenticar alguém e redirecioná-lo para onde ele precisa ir. Este método também é útil se você quiser fornecer um link 'Logout' na área de membros do seu aplicativo:

 logout de função  pública () { return $ this -> redirect ( $ this -> Auth -> logout ()); }

     

Fazer logoff de usuários que efetuaram login com a autenticação Digest ou Basic é difícil de realizar para todos os clientes. A maioria dos navegadores reterá as credenciais enquanto elas ainda estiverem abertas. Alguns clientes podem ser forçados a efetuar logout enviando um código de status 401. Alterar o domínio de autenticação é outra solução que funciona para alguns clientes.

Decidindo quando executar a autenticação
Em alguns casos, você pode querer usar $this->Auth->user()no método. Isso é possível usando a chave de configuração. As seguintes alterações qual evento para o qual as verificações de autenticação inicial devem ser feitas:beforeFilter(Event $event)checkAuthIn

// Configure o AuthComponent para autenticar em initialize () 
$ this -> Auth -> config ( 'checkAuthIn' ,  'Controller.initialize' );
O valor padrão para checkAuthIné 'Controller.startup'- mas usando 'Controller.initialize'a autenticação inicial é feito antes do beforeFilter() método.

Autorização
Autorização é o processo de garantir que um usuário identificado / autenticado tenha permissão para acessar os recursos que está solicitando. Se ativado, é AuthComponentpossível verificar automaticamente os manipuladores de autorização e garantir que os usuários conectados tenham permissão para acessar os recursos que estão solicitando. Existem vários manipuladores de autorização internos e você pode criar os personalizados para seu aplicativo ou como parte de um plug-in.

ControllerAuthorizeChama isAuthorized()o controlador ativo e usa o retorno para autorizar um usuário. Essa é geralmente a maneira mais simples de autorizar usuários.
O adaptador ActionsAuthorize& CrudAuthorizedisponível no CakePHP 2.x agora foi movido para um plugin separado cakephp / acl .

Configurando manipuladores de autorização
Você configura os manipuladores de autorização usando a authorizechave de configuração. Você pode configurar um ou muitos manipuladores para autorização. O uso de vários manipuladores permite que você ofereça suporte a diferentes maneiras de verificar a autorização. Quando os manipuladores de autorização são verificados, eles serão chamados na ordem em que são declarados. Os manipuladores devem retornar false, se não puderem verificar a autorização ou se a verificação falhar. Os manipuladores devem retornar truese puderem verificar a autorização com êxito. Os manipuladores serão chamados em seqüência até que um passe. Se todas as verificações falharem, o usuário será redirecionado para a página de onde eles vieram. Além disso, você pode suspender toda autorização lançando uma exceção. Você precisará pegar quaisquer exceções lançadas e lidar com elas.

Você pode configurar manipuladores de autorização no seu controlador beforeFilter()ou initialize()métodos. Você pode passar informações de configuração para cada objeto de autorização, usando uma matriz:

// Configuração básica 
$ this -> Auth -> config ( 'authorize' ,  [ 'Controller' ]);

// Passa configurações em 
$ this -> Auth -> config ( 'authorize' ,  [ 
    'Actions'  =>  [ 'actionPath'  =>  'controllers /' ], 
    'Controller' 
]);
Muito parecido com authenticate, authorizeajuda a manter seu código DRY, usando a allchave. Essa chave especial permite definir configurações que são passadas para todos os objetos conectados. A allchave também é exposta como AuthComponent::ALL:

// Passar configurações usando 'all' 
$ this -> Auth -> config ( 'authorizar' ,  [ 
    AuthComponent :: ALL  =>  [ 'actionPath'  =>  'controllers /' ], 
    'Actions' , 
    'Controller' 
]) ;
No exemplo acima, tanto o Actionse Controllerreceberá as configurações definidas para a chave 'all'. Todas as configurações passadas para um objeto de autorização específico substituirão a chave correspondente na chave "todos".

Se um usuário autenticado tentar acessar uma URL que não está autorizado a acessar, ele será redirecionado para o referenciador. Se você não quiser tal redirecionamento (principalmente necessário ao usar o adaptador de autenticação sem monitoração de estado), você pode definir a opção de configuração unauthorizedRedirectcomo false. Isso faz AuthComponent com que um lance em ForbiddenExceptionvez de redirecionar.

Criando objetos de autorização personalizados
Como os objetos de autorização são plugáveis, você pode criar objetos de autorização personalizados em seu aplicativo ou plug-ins. Se, por exemplo, você quisesse criar um objeto de autorização LDAP. Em src / Auth / LdapAuthorize.php você pode colocar o seguinte:

namespace  App \ Auth ;

use  Cake \ Auth \ BaseAuthorize ; 
use  Cake \ Http \ ServerRequest ;

class  LdapAuthorize  extends  BaseAuthorize 
{ 
    public  function  authorize ( $ usuário ,  ServerRequest  $ request ) 
    { 
        // Faça coisas para o ldap aqui. 
    } 
}
Autorizar objetos deve retornar falsese o usuário tiver acesso negado ou se o objeto não puder executar uma verificação. Se o objeto é capaz de verificar o acesso do usuário, truedeve ser retornado. Não é necessário que você estenda BaseAuthorize, apenas que seu objeto de autorização implemente um authorize()método. A BaseAuthorizeclasse fornece vários métodos úteis que são comumente usados.

Usando objetos de autorização personalizados
Depois de criar seu objeto de autorização personalizado, você poderá usá-los incluindo-os na AuthComponentmatriz de autorizações do seu autor:

$ this -> Auth -> config ( 'autorizar' ,  [ 
    'Ldap' ,  // app autorizar objeto. 
    'AuthBag.Combo' ,  // plugin autorizar objeto. 
]);
Usando nenhuma autorização
Se você não quiser usar nenhum dos objetos de autorização incorporados e quiser lidar com as coisas totalmente fora de AuthComponentvocê, você pode definir . Por padrão, começa com definido para . Se você não usar um esquema de autorização, certifique-se de verificar a autorização no seu controlador ou com outro componente.$this->Auth->config('authorize', false);AuthComponentauthorizefalsebeforeFilter()

Tornando Ações Públicas
AuthComponent::allow( $ actions = null )
Muitas vezes, as ações do controlador que você deseja permanecer totalmente públicas ou que não exigem que os usuários façam logon. São AuthComponentpessimistas e padronizam a negação de acesso. Você pode marcar ações como ações públicas usando AuthComponent::allow(). Marcando ações como públicas, AuthComponentnão verificará um usuário conectado nem autorizará a verificação de objetos:

// Permitir todas as ações 
$ this -> Auth -> allow ();

// Permitir apenas a ação do índice. 
$ this -> Auth -> allow ( 'index' );

// Permitir apenas as ações de visualização e índice. 
$ this -> Auth -> allow ([ 'view' ,  'index' ]);
Ao chamá-lo vazio, você permite que todas as ações sejam públicas. Para uma única ação, você pode fornecer o nome da ação como uma string. Caso contrário, use uma matriz.

Você não deve adicionar a ação "login" da sua UsersControllerlista de permissões. Isso causaria problemas com o funcionamento normal de AuthComponent.

Fazendo Ações Requer Autorização
AuthComponent::deny( $ actions = null )
Por padrão, todas as ações requerem autorização. No entanto, depois de tornar as ações públicas, você deseja revogar o acesso público. Você pode fazer isso usando AuthComponent::deny():

// Negar todas as ações. 
$ this -> Auth -> deny ();

// Negar uma ação 
$ this -> Auth -> deny ( 'add' );

// Negar um grupo de ações. 
$ this -> Auth -> deny ([ 'adicionar' ,  'editar' ]);
Ao chamá-lo vazio, você nega todas as ações. Para uma única ação, você pode fornecer o nome da ação como uma string. Caso contrário, use uma matriz.

Usando ControllerAuthorize
ControllerAuthorize permite manipular as verificações de autorização em um retorno de chamada do controlador. Isso é ideal quando você tem autorização muito simples ou precisa usar uma combinação de modelos e componentes para fazer sua autorização e não deseja criar um objeto de autorização personalizado.

O callback é sempre chamado isAuthorized()e deve retornar um booleano para saber se o usuário tem ou não permissão para acessar recursos na requisição. O retorno de chamada é passado ao usuário ativo para que possa ser verificado:

classe  AppController  estende o  controlador 
{ 
    public  function  initialize () 
    { 
        parent :: initialize (); 
        $ this -> loadComponent ( 'Auth' ,  [ 
            'authorize'  =>  'Controller' , 
        ]); 
    }

    public  function  isAuthorized ( $ user  =  null ) 
    { 
        // Qualquer usuário registrado pode acessar funções públicas 
        se  ( ! $ this -> request -> getParam ( 'prefix' ))  { 
            return  true ; 
        }

        // Somente administradores podem acessar as funções administrativas 
        se  ( $ this -> request -> getParam ( 'prefixo' )  ===  'admin' )  { 
            return  ( bool ) ( $ usuário [ 'role' ]  ===  'admin' ) ; 
        }

        // Default deny 
        return  false ; 
    } 
}
O retorno de chamada acima forneceria um sistema de autorização muito simples, em que apenas os usuários com role = admin poderiam acessar as ações que estavam no prefixo admin.

Opções de configuração
As configurações a seguir podem ser definidas no initialize()método do seu controlador ou $this->Auth->config()no seu beforeFilter():

ajaxLogin
O nome de um elemento de visualização opcional para renderizar quando uma solicitação AJAX é feita com uma sessão inválida ou expirada.
allowedActions
Ações do controlador para as quais a validação do usuário não é necessária.
autenticar
Defina como uma matriz de objetos de autenticação que você deseja usar ao registrar usuários. Há vários objetos de autenticação principais; veja a seção sobre Sugestões de leitura antes de continuar .
authError
Erro ao exibir quando o usuário tenta acessar um objeto ou ação para o qual não tem acesso.

Você pode suprimir a mensagem authError de ser exibida definindo este valor como booleano false.

autorizar
Defina como uma matriz de objetos de autorização que você deseja usar ao autorizar usuários em cada solicitação; veja a seção sobre Autorização .
instantâneo
Configurações a serem usadas quando o Auth precisar fazer uma mensagem flash com FlashComponent::set(). As chaves disponíveis são:

element- O elemento a ser usado; o padrão é 'default'.
key- A chave para usar; O padrão é 'auth'.
params- A matriz de parâmetros adicionais a serem usados; O padrão é '[]'.
loginAction
Uma URL (definida como uma string ou matriz) para a ação do controlador que manipula logins. Padrões para /users/login.
loginRedirect
O URL (definido como uma string ou array) para a ação do controlador ao qual os usuários devem ser redirecionados após o login. Esse valor será ignorado se o usuário tiver um Auth.redirectvalor em sua sessão.
logoutRedirect
A ação padrão para redirecionar para depois que o usuário é desconectado. Embora AuthComponentnão manipule o redirecionamento pós-logout, um URL de redirecionamento será retornado AuthComponent::logout(). Padrões para loginAction.
desautorizadoRedirect
Controla o manuseio de acesso não autorizado. Por padrão, o usuário não autorizado é redirecionado para o URL do referenciador ou loginActionou '/'. Se definido como false, uma exceção ForbiddenException é lançada em vez de redirecionar.
armazenamento
Classe de armazenamento a ser usada para registro de usuário persistente. Ao usar o autenticador stateless, você deve definir isso para Memory. Padrões para Session. Você pode passar as opções de configuração para a classe de armazenamento usando o formato de matriz. Por exemplo, para usar uma chave de sessão personalizada, você pode definir storagepara .['className' => 'Session', 'key' => 'Auth.Admin']
checkAuthIn
Nome do evento no qual as verificações de autenticação iniciais devem ser feitas. Padrões para Controller.startup. Você pode configurá-lo para Controller.initialize que a verificação seja feita antes que o beforeFilter() método do controlador seja executado.
Você pode obter valores de configuração atuais chamando $this->Auth->config():: only the configuration option:

$ this -> Auth -> config ( 'loginAction' );

$ this -> redirect ( $ this -> Auth -> config ( 'loginAction' ));
Isso é útil se você quiser redirecionar um usuário para a loginrota, por exemplo. Sem um parâmetro, a configuração completa será retornada.

Ações de teste protegidas por AuthComponent
Consulte a seção Testar Ações que Requerem Autenticação para obter dicas sobre como testar as ações do controlador protegidas por AuthComponent.
