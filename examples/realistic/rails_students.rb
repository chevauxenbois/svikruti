post "/students" do
  permitted = params.require(:student).permit(:student_age, :guardian_phone, :school)
  Rails.logger.info "guardian phone #{permitted[:guardian_phone]}"
  Student.create(permitted)
end
