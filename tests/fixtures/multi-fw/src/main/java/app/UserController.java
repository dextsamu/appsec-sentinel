@RestController
@RequestMapping("/api/users")
public class UserController {
    @GetMapping("/{id}")
    public User get(@PathVariable Long id) { return null; }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public void del(@PathVariable Long id) { }
}
