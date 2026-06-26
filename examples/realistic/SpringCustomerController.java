import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

class CustomerPayload {
  private String fullName;
  private String emailAddress;
  private String panNumber;
}

class SpringCustomerController {
  private CustomerRepository customerRepository;
  private Logger logger;

  @PostMapping("/customers")
  public Customer create(@RequestBody CustomerPayload payload) {
    logger.info("creating customer {}", payload.panNumber);
    return customerRepository.save(payload);
  }
}
