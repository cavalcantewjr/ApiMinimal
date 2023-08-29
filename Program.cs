using ApiMinimal.Data;
using ApiMinimal.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using MiniValidation;
using NetDevPack.Identity.Jwt;
using NetDevPack.Identity.Model;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();


builder.Services.AddDbContext<MinimalContextDb>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"))
    );

builder.Services.AddIdentityEntityFrameworkContextConfiguration(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
    b => b.MigrationsAssembly("ApiMinimal")));

builder.Services.AddIdentityConfiguration();
builder.Services.AddJwtConfiguration(builder.Configuration, "appSettings");

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ExcluirFornecedor",
        policy => policy.RequireClaim("ExcluirFornecedor"));
});

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Minimal API Sample",
        Description = "Developed by Washington Cavalcante learning Eduardo Pires / desenvolvedor.io",
        Contact = new OpenApiContact { Name = "Washington Cavalcante", Email = "cavalcantewjr@gmail.com" },
        License = new OpenApiLicense { Name = "MIT", Url = new Uri("https://opensource.org/licenses/MIT") }
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Insira o token JWT desta maneira: Bearer {seu JWS}",
        Name = "Authorization",
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

var app = builder.Build();


if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthConfiguration();
app.UseHttpsRedirection();

app.MapPost("/registro", [AllowAnonymous] async (
    SignInManager<IdentityUser> signInManager,
    UserManager<IdentityUser> userManager,
    IOptions<AppJwtSettings> appJwtSettings,
    RegisterUser registerUser) =>
{
    if (registerUser == null)
        return Results.BadRequest("Usuário não encontrado.");

    if (!MiniValidator.TryValidate(registerUser, out var erros))
        return Results.ValidationProblem(erros);

    var user = new IdentityUser
    {
        UserName = registerUser.Email,
        Email = registerUser.Email,
        EmailConfirmed = true
    };

    var result = await userManager.CreateAsync(user, registerUser.Password);

    if (!result.Succeeded)
        return Results.BadRequest(result.Errors);

    var jwt = new JwtBuilder()
                .WithUserManager(userManager)
                .WithJwtSettings(appJwtSettings.Value)
                .WithEmail(user.Email)
                .WithJwtClaims()
                .WithUserClaims()
                .WithUserRoles()
                .BuildUserResponse();

    return Results.Ok(jwt);

})
    .ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("RegistrarUsuario")
    .WithTags("Usuario");


app.MapPost("/login", [AllowAnonymous] async (
    SignInManager<IdentityUser> signInManager,
    UserManager<IdentityUser> userManager,
    IOptions<AppJwtSettings> appJwtSettings,
    LoginUser loginUser) =>
{
    if (loginUser == null)
        return Results.BadRequest("Usuário não encontrado.");

    if (!MiniValidator.TryValidate(loginUser, out var erros))
        return Results.ValidationProblem(erros);

    var result = await signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, true, true);

    if (result.IsLockedOut)
        return Results.BadRequest("Usuário bloqueado.");

    if (!result.Succeeded)
        return Results.BadRequest("Usuário ou senha inválidos.");

    var jwt = new JwtBuilder()
                .WithUserManager(userManager)
                .WithJwtSettings(appJwtSettings.Value)
                .WithEmail(loginUser.Email)
                .WithJwtClaims()
                .WithUserClaims()
                .WithUserRoles()
                .BuildUserResponse();

    return Results.Ok(jwt);

})
    .ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("LoginUsuario")
    .WithTags("Usuario");



app.MapGet("/fornecedor", [AllowAnonymous] async (
    MinimalContextDb context) =>
    await context.Fornecedores.ToListAsync())
    .WithName("GetFornecedor")
    .WithTags("Fornecedor");

app.MapGet("/fornecedor/{id}", [Authorize] async (
    Guid id,
    MinimalContextDb context) =>

    await context.Fornecedores.FindAsync(id)
    is Fornecedor fornecedor
        ? Results.Ok(fornecedor)
        : Results.NotFound())
    .Produces<Fornecedor>(StatusCodes.Status200OK)
    .Produces<Fornecedor>(StatusCodes.Status404NotFound)
    .WithName("GetFornecedorPorId")
    .WithTags("Fornecedor");

app.MapPost("/fornecedor", [Authorize] async (
    MinimalContextDb context,
    Fornecedor fornecedor
    ) =>
{
    if(!MiniValidator.TryValidate(fornecedor, out var errors))
        return Results.ValidationProblem(errors);

    context.Fornecedores.Add(fornecedor);
    var result = await context.SaveChangesAsync();

    return result > 0 ? Results.CreatedAtRoute("GetFornecedorPorId", new { id = fornecedor.Id, fornecedor}) 
                      : Results.BadRequest("Houve um problema ao salvar o registro.");
})
    .ProducesValidationProblem()
    .Produces<Fornecedor>(StatusCodes.Status201Created)
    .Produces<Fornecedor>(StatusCodes.Status400BadRequest)
    .WithName("PostFornecedor")
    .WithTags("Fornecedor");

app.MapPut("fornecedor/{id}", [Authorize] async (
    Guid id,
    MinimalContextDb context,
    Fornecedor fornecedor) =>
{ 
    var fornecedorBanco = await context.Fornecedores.AsNoTracking().FirstOrDefaultAsync(f => f.Id == id);
    if(fornecedorBanco == null) return Results.NotFound(id);

    if (!MiniValidator.TryValidate(fornecedor, out var errors))
        return Results.ValidationProblem(errors);

    context.Fornecedores.Update(fornecedor);
    var result = await context.SaveChangesAsync();

    return result > 0 ? Results.NoContent()
                      : Results.BadRequest("Houve um problema para atualizar o registro.");
                
})
    .ProducesValidationProblem()
    .Produces<Fornecedor>(StatusCodes.Status204NoContent)
    .Produces<Fornecedor>(StatusCodes.Status400BadRequest)
    .WithName("PutFornecedor")
    .WithTags("Fornecedor");

app.MapDelete("fornecedor/{id}", [Authorize] async (
    Guid id,
    MinimalContextDb context) =>
{
    var fornecedor = await context.Fornecedores.FindAsync(id);
    if (fornecedor == null) return Results.NotFound(id);


    context.Fornecedores.Remove(fornecedor);
    var result = await context.SaveChangesAsync();

    return result > 0 ? Results.NoContent()
                      : Results.BadRequest("Houve um problema para atualizar o registro.");

})
    .Produces<Fornecedor>(StatusCodes.Status404NotFound)
    .Produces<Fornecedor>(StatusCodes.Status204NoContent)
    .Produces<Fornecedor>(StatusCodes.Status400BadRequest)
    .RequireAuthorization("ExcluirFornecedor")
    .WithName("DeleteFornecedor")
    .WithTags("Fornecedor");


app.Run();
