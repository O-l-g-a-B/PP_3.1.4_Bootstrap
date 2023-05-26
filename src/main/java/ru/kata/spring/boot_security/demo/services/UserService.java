package ru.kata.spring.boot_security.demo.services;


import ru.kata.spring.boot_security.demo.model.User;

import java.util.List;

public interface UserService {

    void saveUser(User user);

    void deleteUser(Long id);

    void updateUser(long id, User user);

    User findByUsername(String username);

    User findById(long id);

    List<User> getAllUsers();

}
