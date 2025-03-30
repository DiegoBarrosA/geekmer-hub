package one.expressdev.geekmer_hub;

@RestController
public class HomeController {

    @GetMapping("/")
    public String serveIndex(@RequestParam(required = false) String name) {
        return "index";
    }
}
