# 개요

Spring Boot의 Filter 기능을 활용하여 클라이언트 헤더에서 JWT를 추출하고 인증을 처리하는 경우가 있습니다. 이때, 토큰에 포함된 `userId`를 기반으로 DB를 조회하여 인증 정보의 유효성을 검사하는 로직이 포함됩니다. 인증이 필요한 API 요청은 모두 이 필터를 거치게 되며, 이 과정을 RDBMS인 MariaDB와 In-memory Database인 Redis를 각각 사용할 때의 차이를 비교하기 위해 부하 테스트를 진행합니다.

## 테스트 환경

### PC 및 애플리케이션 버전

- Windows 11 Home
- CPU : Ryzen 5600X (4.6Ghz, 6Core, 12Thread)
- RAM : DDR4 32GB (single channel)
- SSD: SK-Hynix Platinum P41 1TB
- MariaDB : 11.4.7-MariaDB (windows)
- Redis :  8.0.2-alpine(docker desktop으로 로컬에서 image 사용)
- apache-jmeter : 5.6.3
    - 짧은 시간에 여러 유저가 REST API를 요청하는 시나리오를 구현하기 위해 사용됩니다.
- visualVM : 22
    - jmeter로 부하 테스트 진행 시 CPU, Heap 사용량을 GUI로 확인하기 위해 사용됩니다.

## 개발 환경 및 디펜던시 정보

### 자바 버전

- Java : corretto-21 (v21.0.7)

### Gradle Dependency

- gradle : 8.8
- spring-boot-3.2.5
- spring-boot-starter-webflux : 웹플럭스는 논블로킹 기반 웹 프레임워크입니다. 짧은 시간에 많은 부하를 테스트하는 환경이므로 Spring MVC보다 더 적합한 프레임워크라고 생각되어 사용했습니다.
- spring-boot-starter-data-redis-reactive: 웹플럭스에서 Redis를 사용하기위한 의존성입니다.
- spring-boot-starter-data-r2dbc: WebFlux 환경에서 RDBMS를 비동기 방식으로 사용하기 위한 커넥터 의존성입니다.
- r2dbc:r2dbc-pool: R2DBC에서 커넥션 풀을 관리하기 위한 의존성입니다.

아래는 위 디펜던시를 설정한 `application.yml` 파일입니다.

```yaml
spring:
  webflux:
    max-in-memory-size: 10MB #BodyExtractors를 사용할 때, 메모리로 읽을 수 있는 최대 바이트 수
  profiles:
    active: local
  r2dbc:
    pool:
      name: r2dbc-pool
      enabled: true # pool 사용여부 default true
      initial-size: 24 # 초기 커넥션 수, 할당된 풀 사이즈가 0일 때 DB 커넥션을 맺을 경우 1이 아니라 이 값으로 풀을 생성합니다.
      max-size: 36 #풀에서 동시에 유지할 수 있는 커넥션의 최대 수를 설정합니다. 동시에 이 커넥션 풀을 가질 수 있습니다. 초과 요청은 대기(pending) 상태로 적재됩니다.
      max-acquire-time: 10s #커넥션을 풀에서 획득하는 데 허용되는 최대 대기 시간입니다. 예를 들어, 커넥션이 모두 사용 중일 때, 이 시간 안에 커넥션이 풀에서 반환되지 않으면 커넥션 획득 시도가 실패하고 예외가 발생합니다.
      max-idle-time: 1m # 커넥션이 풀에서 유휴 상태(아무 작업 없이 놀고 있는 상태)로 유지될 수 있는 최대 시간입니다. 이 시간이 지나면 해당 커넥션은 종료되고 풀에서 제거되어 자원 낭비를 줄입니다. 이 값은 max-life-time보다 작아야 합니다.
      max-create-connection-time: 1m #커넥션 생성 최대 허용 시간
      max-life-time: 2m #각 커넥션의 최대 생존 시간을 의미합니다. 이 시간이 지나면 커넥션이 아직 사용 중이더라도 해당 커넥션은 풀에서 제거되고 새 커넥션으로 대체됩니다.
  data:
    redis:
      host: localhost
      port: 6379
      password: ${REDIS_PW}
      cache-time: 15 #앱 설정 값, 데이터 캐시할 시간 분단위
      lettuce:
        pool:
          enabled: true
          max-active: 10     # 동시에 사용할 수 있는 최대 커넥션 수
          max-idle: 10       # 유휴 상태로 유지할 최대 커넥션 수
          min-idle: 1        # 최소 유휴 커넥션 수
          max-wait: 5s       # 커넥션을 얻기까지 기다릴 최대 시간
```

### Java VM Option

- -Xms4096m : SpringApplication의 초기 Heap Memory 크기를 4GB로 할당합니다.
- -Xmx4096m : SpringApplication의 Max Heap Memory 크기를 4GB로 할당합니다.
- -Dreactor.schedulers.defaultBoundedElasticSize=12 : WebFlux에서 비즈니스 로직 처리 중 작업가능한 쓰레드가 부족할 경우 여분의 쓰레드를`BoundedElastic-n` 라는 이름으로 생성합니다. 기본값은 코어 수 x 10 입니다. 너무 많은 쓰레드를 생성하지 않도록 최대 12개의 쓰레드만 생성하도록 설정했습니다.

```java
-Xms4096m -Xmx4096m -Dreactor.schedulers.defaultBoundedElasticSize=12
```

## 성능 측정

### Jmeter 설정

- 요청 쓰레드 : 10개
- Ramp-up period : 2초
- Loop Count : Infinity
- Duration : 180s
- Startup delay : 3s
- RequestHeader : 요청헤더에 인증 토큰을 설정합니다. (Authorization - `Bearer ${JWT}` )

## API 설정

### SpringSecurity Filter

요청 헤더에 토큰 값을 가져오고 토큰에 있는 userId값을 DB에  조회해서 인증을 확인합니다. 이 때 인증을 Redis, MariaDB로 분기하여 테스트를 진행합니다.

아래는 상세 코드 내용입니다.  `findUserProjectionByUserId` 는 mariaDB에서 바로 값을 조회하는 로직이며 `findUserByUserIdUseCache` 는 Redis에 값이 없을 때 MariaDB에서 1회 조회를 한 뒤 이후에는 Redis로 조회하는 로직입니다.

JwtAuthenticationFilter

```java
@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtUtil jwtUtil;
    private final MemberService memberService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        return ReactiveSecurityContextHolder.getContext()
                .flatMap(context -> {
                    log.info("## SecurityContext exists :  = {}", (Member)context.getAuthentication().getPrincipal());
                    return chain.filter(exchange);
                })
                .switchIfEmpty(Mono.defer(()-> {
                    if (authHeader != null && authHeader.startsWith("Bearer ")) {
                        String token = authHeader.substring(7);
                        String userId = jwtUtil.getUsernameFromToken(token);
                        //DB에서 User를 조회하는 부분
                        return memberService.findUserProjectionByUserId(userId)
                                .filter(user -> jwtUtil.validateToken(token, userId))
                                .map(Member::new)
                                .flatMap(user -> {
                                    Authentication auth = new UsernamePasswordAuthenticationToken(
                                            user, null, user.getAuthorities());
                                    SecurityContext context = new SecurityContextImpl(auth);
                                    return chain.filter(exchange)
                                            .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(context)));
                                });

                    }
                    return chain.filter(exchange);
                }));
        }
}
```

MemberService

```java
//마리아 디비 조회
    @Override
    public Mono<MemberDto> findUserProjectionByUserId(String userId) {
        return memberDao.findUserProjectionByUserId(userId);
    }

    //마리아 디비 1회 조회 후 레디스 캐시
    @Override
    public Mono<MemberDto> findUserByUserIdUseCache(String userId) {
        return redisTemplate.opsForValue().get(userId)
                .switchIfEmpty(
                        memberDao.findUserProjectionByUserId(userId)
                                .flatMap(member -> {
                                            if(member == null) return Mono.empty();// null cache 방지
                                            return redisTemplate.opsForValue()
                                                    .set(userId, member, Duration.ofMinutes(cacheTime))
                                                    .thenReturn(member);
                                        }

                                ).onErrorResume(e ->
                                {
                                    return memberDao.findUserProjectionByUserId(userId);
                                })

                );
    }
```

### Cotroller

위 Filter에서 생성된 유저 객체(`Principal`)를 Controller에서 받아와서 클라이언트에게 사용자 이름이 담긴 메시지를 전달합니다.

```java
@GetMapping("/me")
    @PreAuthorize("hasAnyAuthority('USER_ROLE', 'ADMIN_ROLE')")
    public Mono<ResponseEntity<String>> getCurrentUser(Mono<Principal> principal) {
        return principal
                .map(Principal::getName)
                .map(name -> ResponseEntity.ok("Hello, " + name + "! You are authenticated."))
                .defaultIfEmpty(ResponseEntity.status(401).body("Unauthorized"));
    }
```

## Redis

### 기록

| Label | # Samples | Average | Min | Max | Std. Dev. | Error % | Throughput | Received KB/sec | Sent KB/sec | Avg. Bytes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| /users/me | 527,240 | 3 | 1 | 1011 | 20.77 | 0.00% | 2929.11111 | 906.77 | 1161.35 | 317 |
| TOTAL | 527,240 | 3 | 1 | 1011 | 20.77 | 0.00% | 2929.11111 | 906.77 | 1161.35 | 317 |

### CPU

### Heap

## MariaDB

### 기록

| Label | # Samples | Average | Min | Max | Std. Dev. | Error % | Throughput | Received KB/sec | Sent KB/sec | Avg. Bytes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| /users/me | 133,853 | 13 | 0 | 5042 | 246.41 | 0.24% | 734.24575 | 231.47 | 290.41 | 322.8 |
| TOTAL | 133,853 | 13 | 0 | 5042 | 246.41 | 0.24% | 734.24575 | 231.47 | 290.41 | 322.8 |

### CPU
![Image](https://github.com/user-attachments/assets/4aa82520-8f2c-482d-8c72-f642c1e55910)

### Heap
![Image](https://github.com/user-attachments/assets/5222a2cc-4aff-4e48-a7c6-761911714f78)


## 결론

Redis에서 유저를 조회했을 때, MariaDB에 비해 처리량(Throughput)이 약 4배 정도 높았으며, 표준 편차(Std. Dev.)도 더 적은 것으로 나타났습니다. MariaDB의 자원 사용량을 확인해 보면, 충분한 자원을 활용하지 못했음을 알 수 있습니다. 이는 SSD와 CPU 간의 속도 차이로 인해 병목현상이 발생했기 때문으로 해석할 수 있습니다.

## 기타

### Redis 직렬화

Redis를 사용하여 캐시를 구현할 때는, Java 객체를 JSON 형태로 직렬화하고 다시 역직렬화하는 과정이 필요합니다. 이 과정에서 **객체의 모든 속성**이 JSON으로 정확히 표현되어야 하며, 역직렬화 시에도 해당 속성을 올바르게 매핑할 수 있어야 합니다.

테스트에 사용된 `Member` 클래스는 Spring Security의 `UserDetails`를 구현하고 있는데, 예를 들어 `getAuthorities()`와 같은 오버라이드된 메서드는 해당 클래스의 명시적인 필드로 존재하지 않기 때문에, JSON → Java 객체로 역직렬화할 때 오류가 발생할 수 있습니다.

이를 방지하기 위해, 캐시에 저장하는 객체로는 인증 관련 로직이나 복잡한 메서드가 포함되지 않은 **`MemberDto`와 같은 단순한 데이터 전달 객체(DTO)**를 사용하는 것이 좋습니다. DTO는 직렬화/역직렬화에 적합하도록 필요한 필드만 포함하며, getter/setter를 통해 값에 접근할 수 있어 Redis 캐시에 적합합니다.

```java
public class Member implements UserDetails, Persistable<String> {
    // ...
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority(userRole));
    }
}

```

### 저장할 객체의 Redis 키

### 저장할 객체의 Redis 키

Redis에 데이터를 저장할 때는, 해당 키가 어떤 RDBMS의 테이블에서 유래한 데이터인지 명확히 구분할 수 있도록 키 네이밍 규칙을 정하는 것이 중요합니다. 단순히 `userId`와 같은 값만을 키로 사용하는 경우, 여러 테이블 간 키 충돌이나 데이터 식별의 혼란이 발생할 수 있기 때문입니다.

따라서 일반적으로는 키 앞에 접두사(prefix)를 붙여 **어떤 도메인 또는 테이블에 속한 데이터인지**를 식별할 수 있도록 구성합니다.

예를 들어, `userId`가 `moonsoo`인 회원 정보를 캐싱할 경우, 다음과 같이 키를 설정할 수 있습니다:

```
Redis Key: member_id_moonsoo
```

### 캐시된 객체의 데이터 정합성

객체를 Redis에 캐시하는 경우, 설정된 TTL(캐시 유효 시간) 동안은 Redis에서 해당 값을 조회하여 사용하게 됩니다. 이때 RDBMS에서 `Member` 테이블의 데이터가 삭제되거나 수정되더라도, Redis 캐시가 갱신되지 않으면 변경된 정보가 반영되지 않는 문제가 발생할 수 있습니다.

다음은 Redis 캐시를 갱신하지 않았을 때 발생할 수 있는 상황을 시나리오로 설명한 것입니다:

- `userId`가 `moonsoo`인 사용자가 ADMIN 권한으로 로그인합니다.
- 이후, 다른 ADMIN 사용자가 `moonsoo`의 권한을 USER로 변경합니다.
- 그러나 `moonsoo`의 권한 정보가 여전히 Redis에 ADMIN으로 캐시되어 있기 때문에, 캐시가 만료되기 전까지는 `moonsoo` 사용자가 계속해서 ADMIN 권한을 사용할 수 있게 됩니다.

이처럼 캐시와 DB 간 데이터 정합성 문제가 발생할 수 있으므로, 수정이나 삭제와 같은 변경이 발생했을 때는 해당 캐시를 적절히 갱신하거나 무효화하는 처리가 필요합니다.
