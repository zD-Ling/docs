# Spring Security 介绍

Spring Security 是 Spring 社区的一个项目，强大并支持高度定制的访问控制框架。

## 创建 Spring Security 项目

```xml
<parent>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>3.1.5</version>
  <relativePath/>
</parent>

<dependencies>
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
  </dependency>
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
  </dependency>
</dependencies>
```

## 从数据库查询用户登录

### 读取用户信息

根据用户输入的用户名从数据库中获取，SpringSecurity 通过实现 UserDetailService 接口实现用户查询

```java
@Slf4j
@Service
public class UserDetailServiceImpl implements UserDetailsService {

    private final UserMapper userMapper;

    public UserDetailServiceImpl(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    /**
     * 通过用户名获取用户
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("根据用户名查看用户============》{}",username);
        User user = userMapper.selectOne(new LambdaQueryWrapper<User>().eq(User::getUsername, username));
        if(user == null) {
            log.info("用户不存在============》");
            return null;
        }
        LoginUser loginUser = new LoginUser();
        loginUser.setUser(user);
        return loginUser;
    }
}
```

### 用户信息存储

我们需要让用户进行登录，同时系统需要临时记住登录用户的信息，Spring Security 提供 UserDetails 接口存储登录用户的信息，因此我们需要将数据库用户实体对象实现 UserDetails 接口。

```java
@Data
public class User implements UserDetails {
    /**
     * 用户实体
     */
    private Long id;
    private String username;
    private String password;
    private String avatar;
    private LocalDateTime createTime;
    private LocalDateTime updateTime;

    /**
     * 返回用户权限，默认按照自然顺序排序
     * @return
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    /**
     * 返回用户密码
     * @return
     */
    @Override
    public String getPassword() {
        return user.getPassword();
    }
    /**
     * 返回用户名
     * @return
     */
    @Override
    public String getUsername() {
        return user.getUsername();
    }

    /**
     * 判断用户是否过期，过期用户无法认证
     * true：未过期
     * @return
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 判断用户是否锁定，锁定的用户无法认证
     * true：未锁定
     * @return
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * 判断用户凭据是否过期，无法对凭证过期用户认证
     * true：有效，即未过期
     * @return
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 返回用户是否可用
     * @return
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

### 密码加密

Spring Security 支持多种密码加密方式，如 BcryptPasswordEncoder 在项目中创建配置类进行配置即可。

```java
@Configuration
@EnableWebSecurity // 启用Web安全功能
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

BCryptPasswordEncoder 简单使用

```java
private final PasswordEncoder passwordEncoder;

/**
* 密码加密
* password：密码
* @return 加密后的密码
*/
public Spring passwordEncryption(String password) {
    return passwordEncoder.encode(user.getPassword());
}

/**
* 密码比对
* password：密码原文
* passwordEncryption：加密的密码
* @return 匹配结果
*/
public boolean matchesPasswordEncryption(String password，String passwordEncryption) {
    return passwordEncoder.matches(password, passwordEncryption);
}
```

## Spring Security 认证体系

- SecurityContextHolder：SecurityContextHolder 是 Spring Security 存储身份验证者详细信息的地方。
- SecurityContext：可以是 AuthenticationManager 的输入，以提供用户提供的用于身份验证的凭据或 SecurityContext 中的当前用户。
- Authentication：可以是 AuthenticationManager 的输入，以提供用户提供的用于身份验证的凭据或 SecurityContext 中的当前用户。
- GrantedAuthority：在身份验证上授予主体的权限（即角色、作用域等）。
- AuthenticationManager：定义了 Spring Security 的过滤器如何执行身份验证。
- ProviderManager：AuthenticationManager 最常见的实现。
- AuthenticationProvider：ProviderManager 用来执行特定类型的身份验证。
- Request Credentials withAuthenticationEntryPoint：用于从客户端请求凭据（即重定向到登录页面、发送 WWW-Authenticate 响应等。
- AbstractAuthenticationProcessingFilter：用于身份验证的基本筛选器。这也为高级身份验证流程以及各部分如何协同工作提供了一个很好的概念。

### SecurityContextHolder

Spring Security 身份验证模型的核心是 SecurityContextHolder。它包含 SecurityContext。

![SecurityContextHolder](../public/assets/images/Spring_Security/SecurityContextHolder.jpg)

SecurityContextHolder 是 Spring Security 存储身份验证者详细信息的地方。Spring Security 并不关心 SecurityContextHolder 是如何填充的。如果它包含一个值，它将被用作当前经过身份验证的用户，指示用户已通过身份验证的最简单方法是直接设置 SecurityContextHolder， 创建一个空的 SecurityContext。

```java
// 首先创建一个空的SecurityContext。应该创建一个新的SecurityContext实例，
// 而不是使用SecurityContextHolder.getContext（）.setAuthentication（身份验证）
// 来避免多个线程之间的竞争条件
SecurityContext context = SecurityContextHolder.createEmptyContext();
// 接下来，创建一个新的Authentication对象。
// Spring Security并不关心在SecurityContext上设置了什么类型的身份验证实现。
// 在这里，使用TestingAuthenticationToken，因为它非常简单。
// 更常见的生产场景是UsernamePasswordAuthenticationToken（userDetails、password、authority）
Authentication authentication =
    new TestingAuthenticationToken("username", "password", "ROLE_USER");
context.setAuthentication(authentication);
// 最后，在SecurityContextHolder上设置SecurityContext。
// Spring Security使用此信息进行授权
SecurityContextHolder.setContext(context);
```

如果想要获取认证信息，可以通过 SecurityContext。

```java
SecurityContext context = SecurityContextHolder.getContext();
Authentication authentication = context.getAuthentication();
String username = authentication.getName();
Object principal = authentication.getPrincipal();
Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
```

默认情况下，SecurityContextHolder 使用 ThreadLocal 来存储这些详细信息，这意味着 SecurityContext 始终可用于同一线程中的方法，即使 SecurityContext 没有明确地作为参数传递给这些方法。如果您在处理当前主体的请求后注意清除线程，那么以这种方式使用 ThreadLocal 是非常安全的。Spring Security 的 FilterChainProxy 确保始终清除 SecurityContext。

有些应用程序并不完全适合使用 ThreadLocal，因为它们使用线程的特定方式。例如，Swing 客户端可能希望 Java 虚拟机中的所有线程使用相同的安全上下文。可以在启动时使用策略配置 SecurityContextHolder，以指定希望如何存储上下文。对于独立的应用程序，可以使用 SecurityContextHolder。模式全局策略。其他应用程序可能希望由安全线程派生的线程也采用相同的安全标识。可以通过使用 SecurityContextHolder 来实现这一点。MODE_INHERITABLETHREADLOCAL。以从默认的 SecurityContextHolder 更改模式。MODE_THREADDLOCAL 有两种方式。第一种是设置系统属性。第二种方法是在 SecurityContextHolder 上调用一个静态方法。大多数应用程序不需要更改默认设置。但是，如果这样做了，请查看 JavaDocforSecurityContextHolder 以了解更多信息。

### SecurityContext

SecurityContext 是从 SecurityContextHolder 获得的。SecurityContext 包含一个身份验证对象。

### Authentication

Authentication 接口在 Spring Security 中有两个主要用途：

- AuthenticationManager 的输入，用于提供用户为进行身份验证而提供的凭据。在此场景中使用时，isAuthenticated（）返回 false。
- 表示当前已通过身份验证的用户。可以从 SecurityContext 获取当前身份验证。

Authentication 包含：

- principal：标识用户。当使用用户名/密码进行身份验证时，这通常是 UserDetails 的一个实例。
- credentials：通常是一个密码。在许多情况下，这是在用户经过身份验证后清除的，以确保它不会泄露。
- authorities：GrantedAuthority 实例是授予用户的高级权限。两个例子是角色和作用域。

### GrantedAuthority

GrantedAuthority 实例是授予用户的高级权限。两个例子是角色和作用域。

可以从 Authentication.getAuthorities（）方法获取 GrantedAuthority 实例。此方法提供 GrantedAuthority 对象的集合。毫不奇怪，GrantedAuthority 是授予委托人的权力。此类权限通常是“角色”，例如 ROLE_ADMINISTRATOR 或 ROLE_HR_SUPERVER。这些角色稍后将配置为进行 web 授权、方法授权和域对象授权。Spring Security 的其他部门解释这些权威，并希望他们在场。在使用基于用户名/密码的身份验证时，GrantedAuthority 实例通常由 UserDetailsService 加载。

通常，GrantedAuthority 对象是应用程序范围的权限。它们并不特定于给定的域对象。因此，您可能没有 GrantedAuthority 来表示对编号为 54 的 Employee 对象的权限，因为如果有数千个这样的权限，您将很快耗尽内存（或者，至少会导致应用程序花费很长时间来验证用户）。当然，Spring Security 是专门为处理这一常见需求而设计的，但您应该为此目的使用项目的域对象安全功能。

### AuthenticationManager

AuthenticationManager 用来实现 Spring Security 的认证功能。它是一个接口，常用的实现有 ProviderManager，你也可以自定义实现登录认证流程而不使用 Security 提供的认证管理器（如：需要用户名+密码+验证码/当天内密码错误次数到达某个上限）。

调用 AuthenticationManager 认证之后在 SecurityContextHolder 会存储当前的认证信息，即返回一个 Authentication 对象。

### ProviderManager

ProviderManager 是 AuthenticationManager 最常用的实现。ProviderManager 将委派给 AuthenticationProvider 实例列表。每个 AuthenticationProvider 都有机会指示身份验证应该成功、失败，或者指示它不能做出决定，并允许下游 AuthenticationProvider 做出决定。如果配置的 AuthenticationProvider 实例都不能进行身份验证，则身份验证将失败，并出现 ProviderNotFoundException，这是一种特殊的 AuthenticationException，表示 ProviderManager 未配置为支持传递到它的身份验证类型。

![ProviderManager](../public/assets/images/Spring_Security/ProviderManager.jpg)

在实践中，每个 AuthenticationProvider 都知道如何执行特定类型的身份验证。例如，一个 AuthenticationProvider 可能能够验证用户名/密码，而另一个可能能够验证 SAML 断言。这允许每个 AuthenticationProvider 执行一种非常特定的身份验证类型，同时支持多种类型的身份验证，并且只公开一个 AuthenticationManager bean。

ProviderManager 还允许配置可选的父 AuthenticationManager，在没有 AuthenticationProvider 可以执行身份验证的情况下，会咨询该父 AuthenticationManager。父级可以是任何类型的 AuthenticationManager，但它通常是 ProviderManager 的实例。

![ProviderManagerParent](../public/assets/images/Spring_Security/ProviderManagerParent.jpg)

事实上，多个 ProviderManager 实例可能共享同一个父 AuthenticationManager。在存在多个 SecurityFilterChain 实例的情况下，这种情况有些常见，这些实例有一些共同的身份验证（共享的父 AuthenticationManager），但也有不同的身份验证机制（不同的 ProviderManager 实例）。

![ProviderManagerMoreParent](../public/assets/images/Spring_Security/ProviderManagerMoreParent.jpg)

默认情况下，ProviderManager 会尝试从成功的身份验证请求返回的身份验证对象中清除任何敏感凭据信息。这可以防止诸如密码之类的信息在 HttpSession 中保留的时间超过所需的时间。

例如，当使用用户对象的缓存来提高无状态应用程序的性能时，这可能会导致问题。如果身份验证包含对缓存中对象（如 UserDetails 实例）的引用，并且该引用已删除其凭据，则无法再根据缓存值进行身份验证。如果使用缓存，则需要考虑到这一点。一个显而易见的解决方案是首先在缓存实现或创建返回的 Authentication 对象的 AuthenticationProvider 中制作对象的副本。或者，可以禁用 ProviderManager 上的 eraseCredentialsAfterAuthentication 属性。有关 Javadoc 类，请参阅 Javadoc。

### AuthenticationProvider

您可以将多个 AuthenticationProviders 实例注入 ProviderManager。每个 AuthenticationProvider 都执行特定类型的身份验证。例如，DaoAuthenticationProvider 支持基于用户名/密码的身份验证，而 JwtAuthenticationProvider 则支持对 JWT 令牌进行身份验证。

### 使用 AuthenticationEntryPoint 请求凭据

AuthenticationEntryPoint 用于发送请求客户端凭据的 HTTP 响应。

有时，客户端会主动包含凭据（如用户名和密码）来请求资源。在这些情况下，SpringSecurity 不需要提供从客户端请求凭据的 HTTP 响应，因为它们已经包含在内。

在其他情况下，客户端对未经授权访问的资源发出未经身份验证的请求。在这种情况下，AuthenticationEntryPoint 的实现用于向客户端请求凭据。AuthenticationEntryPoint 实现可能会执行重定向到登录页、使用 WWW-Authenticate 标头进行响应或采取其他操作。

### AbstractAuthenticationProcessingFilter

AbstractAuthenticationProcessingFilter 用作对用户凭据进行身份验证的基本筛选器。在对凭据进行身份验证之前，Spring Security 通常会使用 AuthenticationEntryPoint 请求凭据。

接下来，AbstractAuthenticationProcessingFilter 可以对提交给它的任何身份验证请求进行身份验证。

![AbstractAuthenticationProcessingFilter](../public/assets/images/Spring_Security/AbstractAuthenticationProcessingFilter.jpg)

1. 当用户提交凭据时，AbstractAuthenticationProcessingFilter 会从要进行身份验证的 HttpServlet 请求创建一个身份验证。创建的身份验证类型取决于 AbstractAuthenticationProcessingFilter 的子类。例如，UsernamePasswordAuthenticationFilter 根据 HttpServlet 请求中提交的用户名和密码创建 UsernamePasswordAuthenticationToken。
2. 接下来，身份验证被传递到要进行身份验证的 AuthenticationManager 中。
3. 如果身份验证失败，则选择 Failure。
4. 如果身份验证成功，则为成功.
   1. SessionAuthenticationStrategy 收到新登录的通知。
   2. 身份验证是在 SecurityContextHolder 上设置的。稍后，如果需要保存 SecurityContext 以便在将来的请求中自动设置，则必须显式调用 SecurityContextRepository.saveContext()。
   3. ApplicationEventPublisher 发布 InteractiveAuthenticationSuccessEvent。
   4. AuthenticationSuccessHandler 被调用。

## Spring Security 鉴权方式

SpringSecurity 支持量两种级别的鉴权：

- 请求级别
- 方法级别

### 请求级别的鉴权

默认情况下 SpringSecurity 会对每一个请求都进行身份验证，比如可以设置 /admin 下的请求需要哪些权限，比如:

```java
http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated()
)
```

这个配置的意思就是告诉 SpringSecurity，每一个请求都需要进行身份验证。

### 授权组件工作原理

![HowAuthorizationWorks](../public/assets/images/Spring_Security/HowAuthorizationWorks.jpg)

1. 首先，从 SecurityContextHolder 获取 Authentication。
2. 其次，它将 Authentication 和 HttpServlet 请求传递给 AuthorizationManager。AuthorizationManager 将请求与 authorizeHttpRequests 中的配置进行匹配，并运行相应的规则。
   1. 如果授权被拒绝，则会发布 AuthorizationDeniedEvent，并引发 AccessDeniedException。在这种情况下，ExceptionTranslationFilter 处理 AccessDeniedException。
   2. 如果授予访问权限，则会发布 AuthorizationGrantedEvent，AuthorizationFilter 会继续使用 FilterChain，从而允许应用程序正常处理。

### AuthorizationFilter

AuthorizationFilter 默认为过滤器链的最后一个，这意味着 Spring Security 的身份验证过滤器、漏洞保护和其他过滤器集成不需要授权。如果您在 AuthorizationFilter 之前添加自己的过滤器，它们也不需要授权；

由于 SpringMVC 是由 DispatcherServlet 执行，会在 AuthorizationFilter 之后执行，所以 SpringMVC 的接口需要配置到 authorizeHttpRequests 中

#### 作用范围

AuthorizationFilter 不仅在每一个请求都会执行，每一个调度上都会执行，比如一个请求需要授权，一个页面跳转，访问静态资源等都需要，如下案例：

```java
@Controller
public class MyController {
    @GetMapping("/endpoint")
    public String endpoint() {
        return "endpoint";
    }
}
```

如若你希望拥有访问该接口的权限则需要配置：

```java
http.authorizeHttpRequests((authorize) -> authorize.requestMatchers("/endpoint")
        .permitAll()
        .anyRequest().denyAll()
    )
```

当请求总是被允许或总是被拒绝时，authorizeHttpRequest 就很重要了。在这些情况下，不会查询身份验证，从而加快请求速度。

如果希望要求/endpoint 只能由具有 USER 权限的最终用户访问，则可以执行以下操作：

```java
@Bean
SecurityFilterChain web(HttpSecurity http) throws Exception {
	http.authorizeHttpRequests((authorize) -> authorize.requestMatchers("/endpoint")
            .hasAuthority('USER')
			.anyRequest().authenticated()
		)
	return http.build();
}
```

上边配置的意思就是/endpoint 请求需要有 USER 权限，否则其它请求只需要认证就可以了。

### 请求匹配

Spring Security 支持两种用于 URI 模式匹配的语言：Ant（如上所述）和正则表达式。

#### 使用 Ant 匹配

Ant 是 Spring Security 用于匹配请求的默认语言，可以使用它来匹配单个端点或目录，甚至可以捕获占位符以供以后使用。还可以对其进行细化，以匹配一组特定的 HTTP 方法。假设您不希望匹配/expendpoint 端点，而是希望匹配/resources 目录下的所有端点。在这种情况下，您可以执行以下操作：

```java
http.authorizeHttpRequests((authorize) -> authorize.requestMatchers("/resource/**")
        .hasAuthority("USER")
        .anyRequest().authenticated()
    )
```

读取此信息的方法是“如果请求是/resources 或某个子目录，则需要 USER 权限；否则，仅需要身份验证”

还可以从请求中提取路径值，如下所示：

```java
http.authorizeHttpRequests((authorize) -> authorize.requestMatchers("/resource/{name}")
        .access(new WebExpressionAuthorizationManager("#name == authentication.name"))
        .anyRequest().authenticated()
    )
```

> Spring Security 只匹配路径。如果要匹配查询参数，则需要一个自定义的请求匹配器。

#### 使用正则表达式匹配

如果想在子目录中应用比\*\*更严格的匹配条件，正则表达式非常有用，例如，考虑一个包含用户名和所有用户名必须是字母数字的规则的路径。可以使用 RegexRequestMatcher 来遵守此规则，如下所示：

```java
http.authorizeHttpRequests((authorize) -> authorize
        .requestMatchers(RegexRequestMatcher.regexMatcher("/resource/[A-Za-z0-9]+"))
        .hasAuthority("USER")
        .anyRequest().denyAll()
    )
```

#### 通过 Http 方法匹配

也可以通过 HTTP 方法匹配规则。这很方便的一个地方是通过授予的权限进行授权，比如授予读取或写入权限。

要求所有 GET 都具有读取权限，所有 POST 都具有写入权限，可以执行以下操作：

```java
http.authorizeHttpRequests((authorize) -> authorize
        .requestMatchers(HttpMethod.GET).hasAuthority("read")
        .requestMatchers(HttpMethod.POST).hasAuthority("write")
        .anyRequest().denyAll()
    )
```

这些授权规则应理解为：“如果请求是 GET，则需要读取权限；否则，如果请求是 POST，则需要写入权限；否则拒绝请求”

#### 按调度程序类型匹配

> XML 当前不支持此功能

如前面所述，Spring Security 默认情况下授权所有调度程序类型。即使 REQUEST 调度上建立的安全上下文会转移到后续调度，但细微的不匹配有时也会导致意外的 AccessDeniedException。

```java
http.authorizeHttpRequests((authorize) -> authorize
        .dispatcherTypeMatchers(DispatcherType.FORWARD, DispatcherType.ERROR).permitAll()
        .requestMatchers("/endpoint").permitAll()
        .anyRequest().denyAll()
    )
```

#### 自定义 Matcher

```java
RequestMatcher printview = (request) -> request.getParameter("print") != null;
http.authorizeHttpRequests((authorize) -> authorize.requestMatchers(printview)
        .hasAuthority("print")
        .anyRequest().authenticated()
    )
```

RequestMatcher 是一个函数式接口，可以使用 Lambda 实现。

但是，如果要从请求中提取值，则需要有一个具体的类，因为这需要重写默认方法。

### 授权请求

一旦匹配了一个请求，就可以通过多种方式对其进行授权，如 permitAll、denyAll 和 hasAuthority。

| 授权规则        | 说明                                                                                 |
| :-------------- | :----------------------------------------------------------------------------------- |
| permitAll       | 该请求不需要授权，是一个公共端点；请注意，在这种情况下，永远不会从会话中检索身份验证 |
| denyAll         | 在任何情况下都不允许提出请求；请注意，在这种情况下，永远不会从会话中检索身份验证     |
| hasAuthority    | 该请求要求身份验证需要在 GrantedAuthority 中有指定的值                               |
| hasRole         | hasAuthority 的快捷方式，前缀为 ROLE\_或配置为默认前缀的任何内容                     |
| hasAnyAuthority | 该请求要求身份验证需要在 GrantedAuthority 中有任意一个匹配的值                       |
| hasAnyRole      | hasAnyAuthority 的快捷方式，前缀为 ROLE\_或配置为默认前缀的任何内容                  |
| access          | 请求使用此自定义 AuthorizationManager 来确定访问权限                                 |

如下所示：

```java
@Bean
SecurityFilterChain web(HttpSecurity http) throws Exception {
	http.authorizeHttpRequests(authorize -> authorize  (1)
            .dispatcherTypeMatchers(FORWARD, ERROR).permitAll() (2)
			.requestMatchers("/static/**", "/signup", "/about").permitAll() (3)
			.requestMatchers("/admin/**").hasRole("ADMIN") (4)
			.requestMatchers("/db/**").access(allOf(hasAuthority('db'), hasRole('ADMIN')))   (5)
			.anyRequest().denyAll()                                                (6)
		);

	return http.build();
}
```

1. 指定了多个授权规则。每一条规则都是按照它们顺序执行。
2. 允许 Dispatche 的 FORWARD 和 ERROR 允许 Spring MVC 呈现视图，允许 Spring Boot 呈现错误。
3. 我们指定了多个 URL 模式，任何用户都可以访问。具体来说，如果 URL 以“/resources/”、“/signup”、“/about”开头，则任何用户都可以访问请求。
4. 任何以“/admin/”开头的 URL 都将被限制为具有“role*admin”角色的用户。您会注意到，由于我们调用的是 hasRole 方法，因此不需要指定“ROLE*”前缀。
5. 任何以“/db/”开头的 URL 都要求用户同时获得“db”权限和“ROLE*ADMIN”。你会注意到，由于我们使用的是 hasRole 表达式，因此不需要指定“ROLE*”前缀。
6. 任何尚未在上匹配的 URL 都被拒绝访问。如果不想意外忘记更新授权规则，这是一个很好的策略。

### 方法级别鉴权

除了在请求级别建模授权之外，Spring Security 还支持在方法级别建模。通过使用@EnableMethodSecurity 注解对任意一个@Configuration 类使用即可。

> 默认情况下，Spring Boot Starter Security 不会激活方法级授权

#### 迁移到 EnableMethodSecurity

如果您正在使用@EnableGlobalMethodSecurity，则应迁移到@EnableMethodSecurity。在 SpringSecurity6 版本中@EnableGlobalMethodSecurity 和`<global-method-security>`分别被弃用，取而代之的是@EnableMethodSecurity 和 `<method-security>`。默认情况下，新的 annotation 和 XML 元素会激活 pre-post 注解，并在内部使用 AuthorizationManager。意思就是以下两个代码是等效的：

```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
和
@EnableMethodSecurity
```

对于不需要请求前鉴权的方法应该将其关闭

```java
@EnableGlobalMethodSecurity(securedEnabled = true)
或
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = false)
```

#### 新老 API 区别

此@EnableMethodSecurity 替代了@EnableGlobalMethodSecurity。提供了以下改进：

1. 使用简化的 AuthorizationManager API，而不是元数据源、配置属性、决策管理器和投票者。这简化了重用和自定义。
2. 支持直接基于 bean 的配置，而不需要扩展 GlobalMethodSecurityConfiguration 来自定义 bean。
3. 使用 Spring AOP 构建，删除抽象并允许您使用 Spring AOP 构建块进行自定义。
4. 检查是否存在冲突的注释，以确保明确的安全配置。
5. 符合 JSR-250。
6. 默认情况下启用@PreAuthorize、@PostAuthorize、@PreFilter 和@PostFilter。

方法授权是方法授权之前和之后的组合。考虑一个以以下方式进行注释的服务 bean：

```java
@Service
public class MyCustomerService {
    @PreAuthorize("hasAuthority('permission:read')")
    @PostAuthorize("returnObject.owner == authentication.name")
    public Customer readCustomer(String id) { ... }
}
```

当方法安全性被激活时，对 MyCustomerService#readCustomer 的给定调用可能如下所示：

![MyCustomerService#readCustomer](../public/assets/images/Spring_Security/HowAuthorizationWorks.jpg)

1. Spring AOP 为 readCustomer 调用其代理方法。在代理的其他顾问中，它调用与@PreAuthorize 切入点匹配的 AuthorizationManagerBeforeMethodInterceptor。
2. 拦截器调用 PreAuthorizationAuthorizationManager.check 方法。
3. 授权管理器使用 MethodSecurityExpressionHandler 解析注解的 SpEL 表达式，并从包含 Authentication 和 MethodInvocation 的 MethodSecurityExpresstionRoot 构造相应的 EvaluationContext。
4. 拦截器使用此上下文来评估表达式；具体地说，它从 Authentication 那里读取身份验证，并检查它是否具有权限：在其权限集合中读取。
5. 如果评估通过，那么 SpringAOP 将继续调用该方法。
6. 如果不是，则拦截器发布 AuthorizationDeniedEvent 并抛出 AccessDeniedException，ExceptionTranslationFilter 捕获该异常并向响应返回 403 状态代码。
7. 方法返回后，Spring AOP 调用一个 AuthorizationManagerAfterMethodInterceptor，它与@PostAuthorize 切入点匹配，操作与上面相同，但使用 PostAuthorizationManager。
8. 如果评估通过（在这种情况下，返回值属于已登录的用户），则正常继续处理。
9. 如果不是，则拦截器发布 AuthorizationDeniedEvent 并抛出 AccessDeniedException，ExceptionTranslationFilter 捕获并向响应返回 403 状态代码。

> 如果没有在 HTTP 请求的上下文中调用该方法，则可能需要自己处理 AccessDeniedException

#### 注意

- 如上所述，如果一个方法调用涉及多个方法安全性注释，则每次处理一个。这意味着，他们可以被集体地认为是被“捆绑”在一起的。换句话说，要对调用进行授权，所有注释检查都需要通过授权。
- 不能写两个相同的注解。
- 每个注解都有自己的切入点，可以从 AuthorizationMethodPointcuts 中查看细节

### 请求级别和方法级别对比

|           | 请求级别       | 方法级别     |
| --------- | -------------- | ------------ |
| 授权类型  | 粗粒度         | 细粒度       |
| 配置位置  | 在配置类中配置 | 在方法上配置 |
| 配置样式  | DSL            | 注解         |
| 授权定义· | 编程式         | SpEL 表达式  |

主要的权衡似乎是你希望你的授权规则位于何处。重要的是要记住，当你使用基于注释的方法安全性时，未注释的方法是不安全的。为了防止这种情况，请在 HttpSecurity 实例中声明一个兜底授权规则。

### 常用注解

SpringSecurity 方法安全性一般通过注解实现，常用的注解有：

- @PreAuthorize：方法进入前的权限校验，条件符合则可调用方法，否则抛出 AccessDeniedException 返回 403。
- @PostAuthorize：方法返回的权限校验，返回值符合条件返回结果，否则抛出 AccessDeniedException 返回 403。
- @PreFilter：方法调用前的数据过滤，会过滤符合条件的数据，调用方法，否则返回 403。
- @PostFilter：方法返回过滤后的数据。

@PreAuthorize 和@PostAuthorize 的示例：

```java
// 如果具有 ums:user:list 权限则可访问hello方法
@PreAuthorize("hasAuthority('ums:user:list')")
// 如果返回值长度大于4则正常返回，returnObject是返回值，固定写法
@PostAuthorize("returnObject.length() > 4")
@GetMapping("hello")
public String hello() {

    return "hello";
}
```

@PreFilter 和 @PostFilter 示例：

```java
@PostFilter("filterObject.username.length() > 3")
@GetMapping("user")
public List<UmsUser> searchUserList() {
    System.out.println("返回用户");
    List<UmsUser> users = new ArrayList<>();
    UmsUser umsUser = new UmsUser();
    umsUser.setUsername("无影");
    UmsUser umsUser1 = new UmsUser();
    umsUser1.setUsername("稻草~~");
    UmsUser umsUser2 = new UmsUser();
    umsUser2.setUsername("高粱~");
    users.add(umsUser);
    users.add(umsUser1);
    users.add(umsUser2);
    return users;
}
```

当条件成立时方法才会返回数据，否则返回 403

### 在类或接口级别使用

```java
@Controller
@PreAuthorize("hasAuthority('ROLE_USER')")
public class MyController {
    @GetMapping("/endpoint")
    public String endpoint() { ... }
}
```

那么接口或类中的方法都具备 ROLE_USER 权限才可访问

```java
@Controller
@PreAuthorize("hasAuthority('ROLE_USER')")
public class MyController {
    @GetMapping("/endpoint")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String endpoint() { ... }
}
```

如果方法上也定义了权限，则会覆盖类上的权限

### 方法鉴权工作原理

Spring Security 的方法授权支持非常方便：

- 提取细粒度授权逻辑；例如，当方法参数和返回值有助于授权决策时。
- 在服务层强制执行安全性。
- 在风格上倾向于基于注释而非基于 HttpSecurity 的配置。

## 前后端分离结合 JWT 实现前后端登录授权 RBAC 模型

### JWT 使用

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>
<!-- JDK8以上需要加入以下依赖 -->
<dependency>
    <groupId>javax.xml.bind</groupId>
    <artifactId>jaxb-api</artifactId>
    <version>2.3.1</version>
</dependency>
```

创建工具类，用户创建（生成）token 以及解析 token。

```java
/**
 * JWT工具类，用于生成和解析JWT令牌
 * 提供创建带过期时间的JWT令牌和解析验证JWT令牌的功能
 */
@Component
public class JwtUtil {

    /**
     * JWT签名密钥，用于签名和验证JWT令牌
     * 注意：在生产环境中应使用更安全的密钥管理方式
     */
    private final String signingKey = "123456";

    /**
     * 创建JWT令牌
     *
     * @param claims JWT中包含的声明信息，如用户ID、角色等
     * @return 生成的JWT令牌字符串
     */
    public String createToken(Map<String, Object> claims) {
        // 设置令牌过期时间为7天（单位：毫秒）
        long expireTime = 1000 * 60 * 60 * 24 * 7L;

        return Jwts.builder()
                // 设置过期时间
                .setExpiration(new Date(System.currentTimeMillis() + expireTime))
                // 设置JWT负载中的声明信息
                .setClaims(claims)
                // 使用HS256算法和指定密钥对JWT进行签名
                .signWith(SignatureAlgorithm.HS256, signingKey.getBytes(StandardCharsets.UTF_8))
                // 将JWT构建为紧凑的字符串格式
                .compact();
    }

    /**
     * 解析JWT令牌
     *
     * @param token JWT令牌字符串
     * @return 解析出的声明信息
     * @throws io.jsonwebtoken.JwtException 当令牌无效或签名验证失败时抛出异常
     */
    public Claims parseToken(String token) {
        return Jwts.parser()
                // 设置用于验证签名的密钥
                .setSigningKey(signingKey.getBytes(StandardCharsets.UTF_8))
                // 解析并验证JWT令牌的签名和结构
                .parseClaimsJws(token)
                // 获取JWT中包含的声明信息（Claims对象）
                .getBody();
    }
}
```

### 数据库表实现 RBAC 模型

![RBAC](../public/assets/images/Spring_Security/RBAC.png)

![RBAC_Class](../public/assets/images/Spring_Security/RBAC_Class.png)

### MySQL 表

#### menu

| id  | menu_name    | parent_id | type | component | perms     |
| --- | ------------ | --------- | ---- | --------- | --------- |
| 1   | 用户管理新增 | 0         | 2    | null      | user:add  |
| 2   | 用户管理查询 | 0         | 2    | null      | user:list |

#### role

| id  | role_name |
| --- | --------- |
| 1   | 管理员    |
| 2   | 用户      |

#### user

| id  | username | password                               | avatar | create_time | update_time |
| --- | -------- | -------------------------------------- | ------ | ----------- | ----------- |
| 1   | admin    | 123456(BCryptPasswordEncoder 加密得出) | null   | null        | null        |
| 2   | user     | 123456(BCryptPasswordEncoder 加密得出) | null   | null        | null        |

#### role_menu

| id  | role_id | menu_id |
| --- | ------- | ------- |
| 1   | 1       | 1       |
| 2   | 1       | 2       |
| 3   | 2       | 2       |

#### user_role

| id  | user_id | role_id |
| --- | ------- | ------- |
| 1   | 1       | 1       |
| 2   | 2       | 2       |

### User 实体对象

```java
@Data
public class User implements UserDetails, Serializable {

    private Long id;
    private String username;
    private String password;
    private String avatar;
    private LocalDateTime createTime;
    private LocalDateTime updateTime;

    private List<Role> roles;
    private List<String> perms = new ArrayList<>();

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return perms.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }
}

```

### Role 实体对象

```java
@Data
public class Role implements Serializable {

    private Long id;
    private String roleName;

}
```

### Menu 实体对象

```java
@Data
public class Menu implements Serializable {

    private Long id;
    private String menuName;
    private Long parentId;
    private Integer type;
    private String component;
    private String perms;

}
```

### 通过 JWT 认证用户

- 用户通过账号密码登陆，登陆接口不需要拦截，后端接收登陆请求之后。
  - 根据用户名和密码认证，返回 UserDetails。
  - 根据 UUID 生成字符串，通过 JWT 转换为 token。
  - 以 UUID 字符串为 key，UserDetails 为值存入 redis，设置过期时间。
  - 将 JWT 字符串返回给前端。
- 前端再次登陆其它需要已认证才能访问的接口时，在请求头中携带 JWT 字符串，请求头信息可自定义字段，比如命名为：Authentication。
- 后端通过自定义过滤器获取请求头中的 Authentication。
  - 如果不存在则放行，后续的过滤器会处理，放行是因为有一些接口不需要登录就可以访问，需要交给后边的过滤器处理。
  - 如果存在，则解码 jwt，获取到原本存储的 UUID，从 redis 中获取登陆的用户信息。
  - 将用户信息存储到 SecurityContextHolder 中。
  - 最后放行。

### 获取用户信息

根据 SpringSecurity 提供的 UserDetailsService 接口，实现之后重写 loadUserByUsername 方法从 mysql 中获取用户。

```java
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userMapper.selectByUsername(username);
    }
}
```

### 登录方法

在登陆服务层中，通过 AuthenticationManager 获取 UserDetailsService 实现类中的认证信息，之后创建 token。

#### 使用 Security 提供的认证器功能

```java
@RestController
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

        @PostMapping("/regist")
    public Result<Object> regist(@Valid @RequestBody LoginDTO loginDTO) {
        log.info("用户注册======>{}", loginDTO);
        userService.insert(loginDTO);
        return Result.success(null);
    }

    @PostMapping("/login")
    public Result<Object> login(@Valid @RequestBody LoginDTO loginDTO) {
        log.info("用户登录======>{}", loginDTO);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword());
        Authentication authenticate = null;
        try {
            authenticate = authenticationManager.authenticate(authenticationToken);
        } catch (AuthenticationException e) {
            log.error("用户登录失败:{}", e.getMessage(), e);

            return Result.error("用户名或密码错误");
        }
        User user = (User) authenticate.getPrincipal();
        Map<String, Object> map = new HashMap<>();
        map.put("id", user.getId());
        return Result.success(jwtUtil.createToken(map));
    }
}
```

#### 自定义认证

```java
@RestController
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    @PostMapping("/regist")
    public Result<Object> regist(@Valid @RequestBody LoginDTO loginDTO) {
        log.info("用户注册======>{}", loginDTO);
        userService.insert(loginDTO);
        return Result.success(null);
    }

    @PostMapping("/login")
    public Result<Object> login(@Valid @RequestBody LoginDTO loginDTO) {
        log.info("用户登录======>{}", loginDTO);
        User user = userService.login(loginDTO);
        Map<String, Object> map = new HashMap<>();
        map.put("id", user.getId());
        return Result.success(jwtUtil.createToken(map));
    }
}
```

```java
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void insert(LoginDTO loginDTO) {
        User user = new User();
        BeanUtils.copyProperties(loginDTO, user);
        LocalDateTime nowTime = LocalDateTime.now();
        user.setCreateTime(nowTime);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        System.out.println(user);
        userMapper.insert(user);
    }

    @Override
    public User login(LoginDTO loginDTO) {
        User user = userMapper.selectByUsername(loginDTO.getUsername());
        if (user == null) {
            throw new RuntimeException("用户名或密码错误");
        }
        boolean matches = passwordEncoder.matches(loginDTO.getPassword(), user.getPassword());
        if (!matches) {
            throw new RuntimeException("用户名或密码错误");
        }
        return user;
    }
}

```

### 过滤器

```java
@Component
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    // 注入JWT工具类，用于解析和验证JWT令牌
    private final JwtUtil jwtUtil;

    // 注入菜单映射器，用于从数据库获取用户权限信息
    private final MenuMapper menuMapper;

    // 重写过滤器内部方法，处理每个HTTP请求
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 从请求头中获取Authorization字段的值，即JWT令牌
        String token = request.getHeader("Authorization");
        // 检查令牌是否存在，如果为null则继续执行过滤链
        if (token == null) {
            // 跳过JWT验证，继续执行后续过滤器
            doFilter(request, response, filterChain);
            // 返回，不执行后续JWT验证逻辑
            return;
        }
        // 使用try-catch块处理可能的JWT解析异常
        try {
            // 解析JWT令牌获取其中的声明信息
            Claims claims = jwtUtil.parseToken(token);
            // 从声明中获取用户ID并转换为Long类型
            Long userId = Long.valueOf(claims.get("id").toString());
            // 根据用户ID从数据库查询用户拥有的菜单权限
            List<Menu> menuList = menuMapper.selectByUserId(userId);
            // 创建用户对象，用于构建Spring Security认证令牌
            User user = new User();
            // 获取用户权限列表
            List<String> perms = user.getPerms();
            // 遍历用户拥有的菜单列表
            for (Menu menu : menuList) {
                // 将每个菜单的权限添加到用户权限列表中
                perms.add(menu.getPerms());
            }
            // 设置用户的ID
            user.setId(userId);
            // 创建Spring Security认证令牌，包含用户信息和权限
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            // 将认证信息存储到Spring Security上下文中
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            // 继续执行过滤链，让请求继续处理
            doFilter(request, response, filterChain);
            // 捕获处理过程中可能发生的任何异常
        } catch (Exception e) {
            // 将捕获的异常包装为运行时异常并抛出
            throw new RuntimeException(e);
        }
    }
}
```

MenuMapper.xml

```xml
    <select id="selectByUserId" resultType="com.chon1ma.springsecurity.domain.entity.Menu">
        select menu.id,
               menu.menu_name,
               menu.parent_id,
               menu.type,
               menu.component,
               menu.perms
        from user_role
                 join role_menu on user_role.role_id = role_menu.role_id
                 join menu on role_menu.menu_id = menu.id
        where user_role.user_id = #{userId}
    </select>
```

### Spring Security 配置类

使用 Spring Security 提供的认证处理器。

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    // 注入用户详细信息服务实现
    private final UserDetailsServiceImpl userDetailsService;
    // 注入JWT授权过滤器
    private final JwtAuthorizationFilter jwtAuthorizationFilter;

    // 定义安全过滤器链Bean
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 禁用CSRF保护，因为使用JWT进行身份验证
        http.csrf(AbstractHttpConfigurer::disable);
        // 配置请求授权规则
        http.authorizeHttpRequests(auth ->
                // 配置不需要身份验证的路径，允许所有用户访问注册和登录接口
                auth.requestMatchers("/regist", "/login").permitAll()
                // 配置其他所有请求都需要身份验证
                .anyRequest().authenticated());
        // 在UsernamePasswordAuthenticationFilter之前添加JWT授权过滤器
        http.addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);
        // 配置异常处理
        http.exceptionHandling(exc ->
                // 设置认证入口点，处理未认证的请求
                exc.authenticationEntryPoint(authenticationEntryPoint()));
        // 构建并返回安全过滤器链
        return http.build();
    }

	// 定义认证管理器Bean，用于处理用户认证逻辑
	@Bean
	public AuthenticationManager authenticationManager(PasswordEncoder passwordEncoder) {
    	// 创建DAO认证提供者，用于处理用户名密码认证
    	DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    	// 设置密码编码器，用于密码的加密和验证
    	provider.setPasswordEncoder(passwordEncoder);
    	// 设置用户详情服务，用于加载用户信息
    	provider.setUserDetailsService(userDetailsService);
    	// 创建认证管理器，传入认证提供者
    	return new ProviderManager(provider);
	}


    // 定义密码编码器Bean
    @Bean
    public PasswordEncoder passwordEncoder() {
        // 返回BCrypt密码编码器实现
        return new BCryptPasswordEncoder();
    }

    // 定义认证入口点Bean
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        // 返回Lambda表达式实现的认证入口点
        return (request, response, authException) -> {
            // 设置响应状态码为401（未授权）
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            // 设置响应内容类型为JSON
            response.setContentType("application/json;charset=UTF-8");
            // 定义JSON格式的错误响应
            String result = "{\"code\":401,\"message\":\"请先登录\"}";
            // 将错误响应写入响应体
            response.getWriter().write(result);
        };
    }
}
```

自定义认证处理器

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    // 注入JWT授权过滤器
    private final JwtAuthorizationFilter jwtAuthorizationFilter;

    // 定义安全过滤器链Bean
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 禁用CSRF保护，因为使用JWT进行身份验证
        http.csrf(AbstractHttpConfigurer::disable);
        // 配置请求授权规则
        http.authorizeHttpRequests(auth ->
                // 配置不需要身份验证的路径，允许所有用户访问注册和登录接口
                auth.requestMatchers("/regist", "/login").permitAll()
                // 配置其他所有请求都需要身份验证
                .anyRequest().authenticated());
        // 在UsernamePasswordAuthenticationFilter之前添加JWT授权过滤器
        http.addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);
        // 配置异常处理
        http.exceptionHandling(exc ->
                // 设置认证入口点，处理未认证的请求
                exc.authenticationEntryPoint(authenticationEntryPoint()));
        // 构建并返回安全过滤器链
        return http.build();
    }

    // 定义密码编码器Bean
    @Bean
    public PasswordEncoder passwordEncoder() {
        // 返回BCrypt密码编码器实现
        return new BCryptPasswordEncoder();
    }

    // 定义认证入口点Bean
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        // 返回Lambda表达式实现的认证入口点
        return (request, response, authException) -> {
            // 设置响应状态码为401（未授权）
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            // 设置响应内容类型为JSON
            response.setContentType("application/json;charset=UTF-8");
            // 定义JSON格式的错误响应
            String result = "{\"code\":401,\"message\":\"请先登录\"}";
            // 将错误响应写入响应体
            response.getWriter().write(result);
        };
    }
}
```

###
