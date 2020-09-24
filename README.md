## Провайдер аутентификации ЕСИА для ASP.NET Core 3.1

### Установка

Установите пакет [AspNetCore.Security.OAuth.Esia](https://www.nuget.org/packages/AspNetCore.Security.OAuth.Esia/)

### Использование

В `Startup.cs` включаем аутентификацию и задаем параметры:
```csharp
public void ConfigureServices(IServiceCollection services)
{
    // ...
    
    services.AddAuthentication().AddEsia(options =>
    {
        options.ClientId = "xxxxxxxxx"; // идентификатор системы-клиента, обязателен
        options.ClientCertificateProvider = () => new X509Certificate2(...); // сертификат системы-клиента, обязателен
        
        // по умолчанию используются боевые адреса ЕСИА, можно поменять на тестовые:
        // options.AuthorizationEndpoint = EsiaConstants.TestAuthorizationUrl;
        // options.TokenEndpoint = EsiaConstants.TestAccessTokenUrl;
        // options.UserInformationEndpoint = EsiaConstants.TestUserInformationUrl;
        
        // получение контактных данных пользователя (почта, телефон), по умолчанию отключено
        // options.FetchContactInfo = true;
        
        // options.CorrelationCookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Unspecified;
        // options.SaveTokens = true;
    });
    
    // ...
}
```
