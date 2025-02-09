Plugin.define do
  name ".NET Framework"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "The .NET Framework is a proprietary software framework developed by Microsoft that runs primarily on Microsoft Windows. It was the predominant implementation of the Common Language Infrastructure until being superseded by the cross-platform .NET project."
  website "https://dotnet.microsoft.com/en-us/download/dotnet-framework"

  matches [
    {
      :search => "headers[server]",
      :regexp => /MS .NET Remoting/i,
      :name => ".NET Framework Server Header"
    },
  ]
end