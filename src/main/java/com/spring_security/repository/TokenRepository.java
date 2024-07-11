package com.spring_security.repository;

import com.spring_security.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Integer> {

    // t is alias for Token
    // u is alias for User
    @Query("""
        SELECT t FROM Token t\s
        INNER JOIN t.user u\s
        WHERE u.id = :userId AND (t.expired = false OR t.revoked = false)
     \s""")
    List<Token> findAllUserAccessTokens(Integer userId);

    Optional<Token> findByAccessToken(String jwt);

}
