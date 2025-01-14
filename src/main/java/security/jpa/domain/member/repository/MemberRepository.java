package security.jpa.domain.member.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import security.jpa.domain.member.aggregate.entity.Member;

@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {
}
