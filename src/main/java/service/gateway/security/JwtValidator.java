package service.gateway.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import service.gateway.dto.ContextoUsuario;
import service.gateway.dto.RolUsuario;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.UUID;

@Component
public class JwtValidator {

    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public JwtValidator(@Value("${auth.jwks-url}") String jwksUrl) throws MalformedURLException{

        URL url = URI.create(jwksUrl).toURL();

        JWKSource<SecurityContext> jwkSource = JWKSourceBuilder
                .create(url, new DefaultResourceRetriever())
                .build();

        JWSVerificationKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256,jwkSource);

        jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(keySelector);

    }

    public Mono<ContextoUsuario> validar(String token){
        return Mono.fromCallable(()->procesar(token))
                .subscribeOn(Schedulers.boundedElastic());
    }


    private ContextoUsuario procesar(String token) throws Exception {
        JWTClaimsSet claims =  jwtProcessor.process(token,null );

        UUID userId = UUID.fromString(claims.getSubject());
        RolUsuario rol = RolUsuario.valueOf(claims.getStringClaim("rol"));

        return new ContextoUsuario(userId,rol);
    }

}
