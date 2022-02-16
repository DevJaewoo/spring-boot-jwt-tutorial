package com.devjaewoo.springbootjwttutorial.repository;

import com.devjaewoo.springbootjwttutorial.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

//Spring Data JPA
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    //Username을 기준으로 권한 정보와 같이 User 정보를 가져온다.
    //EntityGraph는 쿼리가 수행이 될 때 Lazy 조회가 아닌 Eager 조회로 authorities 정보를 가져온다고 한다.
    @EntityGraph(attributePaths = "authorities")
    Optional<User> findOneWithAuthoritiesByUsername(String username);
}
