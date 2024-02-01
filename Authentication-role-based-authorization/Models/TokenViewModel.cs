namespace Authentication_role_based_authorization.Models
{
    public class TokenViewModel
    {
        public int StatusCode { get; set; }
        public string StatusMessage { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }
}
