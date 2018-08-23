namespace GameStreamDotNet
{
    using Windows.UI.Xaml;
    using Windows.UI.Xaml.Controls;

    public sealed partial class MainPage : Page
    {
        private readonly PairingManager pairingManager;

        public MainPage()
        {
            this.InitializeComponent();
            //this.pairingManager = new SystemNetHttpClientPairingManager();
            this.pairingManager = new WindowsWebHttpClientPairingManager();
        }

        private async void PairButton_Click(object sender, RoutedEventArgs e)
        {
            await this.pairingManager.PairAsync(ipAddressTextBox.Text, outputTextBox);
        }
    }
}
