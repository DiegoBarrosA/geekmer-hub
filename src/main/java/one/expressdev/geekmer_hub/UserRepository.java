package one.expressdev.geekmer_hub;

import one.expressdev.geekmer_hub.User;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<User, Long> {
    User findByUsername(String username);
}
