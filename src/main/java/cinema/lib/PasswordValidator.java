package cinema.lib;

import cinema.dto.request.UserRegistrationDto;
import org.springframework.beans.BeanWrapperImpl;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class PasswordValidator implements ConstraintValidator<Password, UserRegistrationDto> {
    private String field;
    private String fieldMatch;

    public void initialize(Password constraintAnnotation) {
        this.field = constraintAnnotation.field();
        this.fieldMatch = constraintAnnotation.fieldMatch();
    }

    @Override
    public boolean isValid(UserRegistrationDto registrationDto,
                           ConstraintValidatorContext constraintValidatorContext) {
        Object fieldValue = new BeanWrapperImpl(registrationDto)
                .getPropertyValue(field);
        Object fieldMatchValue = new BeanWrapperImpl(registrationDto)
                .getPropertyValue(fieldMatch);
        return fieldValue != null && fieldValue.equals(fieldMatchValue);
    }
}
