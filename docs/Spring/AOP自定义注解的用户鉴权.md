# 基于 AOP 自定义注解的用户鉴权实现

## 从简单认证到复杂权限管理的演进之路

Spring Security 本质上是一层层过滤器组成的体系，但在实际开发中，我们经常会遇到一个常见问题：项目初期只需要简单的用户认证，但随着业务发展需要引入复杂的权限管理，而此时基于 Spring Security 的配置可能需要大量重构。

## 项目中的权限管理挑战

### 初始阶段：简单 JWT 认证

在项目初期，通常只考虑基本的用户登录功能：

- **用户类型单一：** 只有普通消费者
- **功能简单：** 商品浏览、下单、支付
- **权限需求：** 只需要区分登录/未登录状态
- **实现方式：** 简单的用户认证，无复杂权限控制

常见实现方式是使用 Spring MVC 拦截器做 JWT 拦截器：

1. 请求头携带 token 并解析出用户信息
2. 将用户信息存入 ThreadLocal 中

```java
@Component
public class LoginAuthInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }

        String token = request.getHeader("Authorization");

        try {
            Claims claims = JwtUtil.parseJWT(jwtProperties.getSecretKey(), token); // 解析token
            Long id = Long.valueOf(claims.get("id").toString()); // 获取id
            AuthContextUtil.setId(id);
            return true;
        } catch (Exception e) {
            throw new NotLoggedInException(ResultCodeEnum.UNAUTHORIZED);
        }
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        AuthContextUtil.removeId();
    }
}
```

但是这种方式存在以下问题：

1. **无法实现角色权限控制**
2. **无法实现功能权限控制**

如果这时候需要权限控制，引入 Spring Security 就需要重构代码。

### 业务发展：引入 RBAC 模型

随着业务发展，系统需要支持多种角色：

#### 1. 角色类型增加

- **管理员：** 添加、删除、修改商品、查看订单、查看用户信息
- **商家：** 添加、删除、修改商品、查看订单
- **客服：** 处理售后、查看订单
- **财务人员：** 查看订单、对账
- **普通用户：** 浏览商品、下单、支付

#### 2. 功能权限细分

- **商品管理：** 添加、删除、修改商品
- **订单管理：** 查看订单、处理售后
- **用户管理：** 查看用户信息、禁用账号
- **数据报表：** 查看订单、对账

这是典型的从小型应用向企业级应用演进的案例。初始时业务简单，无需复杂权限管理，但随着业务扩展和用户类型多样化，必须引入 RBAC 来精细化控制不同角色的访问权限，确保系统安全性和功能隔离。

## 重构 Spring MVC 拦截器引入 Spring Security 的痛点

### 1. 代码重构工作量大

- **配置文件迁移：** 需要将原有的拦截器配置迁移到 Spring Security 的安全配置
- **认证逻辑重写：** 原有的 JWT 解析和用户信息处理逻辑需要适配 Spring Security 的认证机制
- **异常处理调整：** 需要将自定义异常处理转换为 Spring Security 的标准异常处理流程

### 2. 学习成本和配置复杂

- **学习曲线陡峭：** Spring Security 配置复杂，需要深入理解 SecurityConfig、FilterChain 等概念
- **配置冲突：** 新旧安全配置可能存在冲突，需要仔细处理

### 3. 侵入性强

- **代码修改范围广：** 需要修改 Controller 层、Service 层等多个层级的代码
- **依赖耦合：** 业务代码与 Spring Security 深度耦合，后期维护困难

### 4. 灵活性受限

- **定制化困难：** Spring Security 标准配置可能不完全符合业务需求
- **扩展性差：** 需要绕过 Spring Security 的默认机制进行自定义开发

## 基于 AOP 自定义注解实现鉴权的优势

### 1. 低侵入性

- **无业务代码侵入：** 只需在需要鉴权的方法上添加自定义注解
- **保持原有架构：** 无需改变现有的拦截器和业务逻辑结构

### 2. 灵活性强

- **按需配置：** 可以根据具体方法需要灵活配置权限要求
- **细粒度控制：** 支持方法级别的权限控制，精确到具体功能点

### 3. 易于维护

- **集中管理：** 权限逻辑集中在 AOP 切面中统一处理
- **易于扩展：** 新增权限类型或验证规则只需修改切面逻辑

### 4. 与现有架构兼容

- **平滑过渡：** 可以在保留现有 JWT 拦截器的基础上逐步引入
- **渐进式实施：** 可以先在部分功能上使用，逐步扩展到全系统

### 5. 性能优势

- **按需执行：** 只在标注了注解的方法上执行权限检查
- **缓存友好：** 可以结合 Redis 等缓存机制优化权限验证性能

### 6. 开发效率高

- **开发简单：** AOP 切面开发相对简单，学习成本低
- **测试友好：** 权限逻辑与业务逻辑分离，便于单元测试

## 自定义注解实现方案详解

### 1. 定义自定义权限注解

首先，我们需要定义一个权限注解，用于标识需要权限验证的方法：

```java
@Target(ElementType.METHOD)  // 仅用于方法
@Retention(RetentionPolicy.RUNTIME)  // 运行时保留
@Documented  // 生成文档时包含
public @interface RequirePermission {
    /**
     * 需要的权限值
     */
    String value() default "";

    /**
     * 需要的角色
     */
    String[] roles() default {};

    /**
     * 是否需要登录
     */
    boolean requireLogin() default true;
}
```

### 2. 创建权限验证切面

接下来，我们创建一个 AOP 切面来处理权限验证逻辑：

```java
@Aspect
@Component
public class PermissionAspect {

    private final UserService userService;
    private final RedisTemplate<String, Object> redisTemplate;

    public PermissionAspect(UserService userService, RedisTemplate<String, Object> redisTemplate) {
        this.userService = userService;
        this.redisTemplate = redisTemplate;
    }

    @Around("@annotation(requirePermission)")
    public Object checkPermission(ProceedingJoinPoint joinPoint, RequirePermission requirePermission) throws Throwable {

        // 获取当前用户ID
        Long userId = AuthContextUtil.getId();

        // 检查是否需要登录
        if (requirePermission.requireLogin() && userId == null) {
            throw new NotLoggedInException("用户未登录");
        }

        // 如果用户未登录且不需要登录，直接执行方法
        if (!requirePermission.requireLogin() && userId == null) {
            return joinPoint.proceed();
        }

        // 获取用户权限
        String userPermissionsKey = "user:permissions:" + userId;
        Set<String> userPermissions = (Set<String>) redisTemplate.opsForSet().members(userPermissionsKey);

        // 如果缓存中没有权限信息，从数据库获取
        if (userPermissions == null || userPermissions.isEmpty()) {
            userPermissions = userService.getUserPermissions(userId);
            // 缓存权限信息，设置过期时间
            redisTemplate.opsForSet().add(userPermissionsKey, userPermissions.toArray());
            redisTemplate.expire(userPermissionsKey, Duration.ofHours(2));
        }

        // 检查权限
        String requiredPermission = requirePermission.value();
        if (StringUtils.hasText(requiredPermission) && !userPermissions.contains(requiredPermission)) {
            throw new AccessDeniedException("权限不足，无法访问该资源");
        }

        // 检查角色
        String[] requiredRoles = requirePermission.roles();
        if (requiredRoles.length > 0) {
            Set<String> userRoles = (Set<String>) redisTemplate.opsForSet().members("user:roles:" + userId);
            if (userRoles == null || userRoles.isEmpty()) {
                userRoles = userService.getUserRoles(userId);
                redisTemplate.opsForSet().add("user:roles:" + userId, userRoles.toArray());
                redisTemplate.expire("user:roles:" + userId, Duration.ofHours(2));
            }

            boolean hasRequiredRole = Arrays.stream(requiredRoles)
                    .anyMatch(userRoles::contains);

            if (!hasRequiredRole) {
                throw new AccessDeniedException("角色不足，无法访问该资源");
            }
        }

        // 执行原方法
        return joinPoint.proceed();
    }
}
```

### 3. 在 Controller 中使用注解

在需要权限控制的 Controller 方法上使用自定义注解：

```java
@RestController
@RequestMapping("/api/products")
public class ProductController {

    @PostMapping
    @RequirePermission(value = "product:add", roles = {"admin", "merchant"})
    public Result addProduct(@RequestBody Product product) {
        productService.addProduct(product);
        return Result.success("商品添加成功");
    }

    @DeleteMapping("/{id}")
    @RequirePermission(value = "product:delete", roles = {"admin"})
    public Result deleteProduct(@PathVariable Long id) {
        productService.deleteProduct(id);
        return Result.success("商品删除成功");
    }

    @PutMapping("/{id}")
    @RequirePermission(value = "product:edit", roles = {"admin", "merchant"})
    public Result updateProduct(@PathVariable Long id, @RequestBody Product product) {
        productService.updateProduct(id, product);
        return Result.success("商品更新成功");
    }

    @GetMapping("/{id}")
    @RequirePermission(requireLogin = true)  // 仅需要登录，不检查具体权限
    public Result getProduct(@PathVariable Long id) {
        Product product = productService.getProductById(id);
        return Result.success(product);
    }

    @GetMapping("/list")
    public Result getProductList() {
        List<Product> products = productService.getAllProducts();
        return Result.success(products);
    }
}
```

### 4. 权限管理服务

实现权限管理相关的服务：

```java
@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    public UserService(UserRepository userRepository,
                      RoleRepository roleRepository,
                      PermissionRepository permissionRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
    }

    /**
     * 获取用户权限
     */
    public Set<String> getUserPermissions(Long userId) {
        // 从数据库获取用户权限
        return permissionRepository.findPermissionsByUserId(userId);
    }

    /**
     * 获取用户角色
     */
    public Set<String> getUserRoles(Long userId) {
        // 从数据库获取用户角色
        return roleRepository.findRolesByUserId(userId);
    }
}
```

### 5. 异常处理

创建权限相关的异常处理：

```java
@RestControllerAdvice
public class PermissionExceptionHandler {

    @ExceptionHandler(NotLoggedInException.class)
    public Result handleNotLoggedIn(NotLoggedInException e) {
        return Result.error(ResultCodeEnum.UNAUTHORIZED.getCode(), e.getMessage());
    }

    @ExceptionHandler(AccessDeniedException.class)
    public Result handleAccessDenied(AccessDeniedException e) {
        return Result.error(ResultCodeEnum.FORBIDDEN.getCode(), e.getMessage());
    }
}
```

## 实现方案的优势

### 1. 易于使用

只需要在需要权限控制的方法上添加注解即可，使用简单直观。

### 2. 灵活配置

可以根据不同方法的需要配置不同的权限和角色要求。

### 3. 性能优化

通过 Redis 缓存用户权限和角色信息，避免频繁查询数据库。

### 4. 易于扩展

可以轻松添加新的权限验证逻辑，如 IP 限制、时间限制等。

### 5. 统一管理

所有权限验证逻辑集中在切面中，便于统一管理和维护。

## 最佳实践建议

1. **权限粒度控制：** 根据业务需要合理设计权限粒度，避免过于细化或过于粗放
2. **缓存策略：** 合理设置缓存过期时间，平衡性能和数据一致性
3. **异常处理：** 统一异常处理，提供友好的错误信息
4. **日志记录：** 记录权限验证失败的日志，便于问题排查和安全审计
5. **权限预加载：** 在用户登录时预加载权限信息，提升首次访问性能

通过以上实现方案，我们可以在保持原有架构的基础上，灵活地实现方法级别的权限控制，既满足了业务发展的需求，又避免了重构带来的风险。
