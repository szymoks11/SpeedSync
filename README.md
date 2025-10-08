# SpeedSync

<p align="center">
  <picture>
    <img alt="SpeedSync" src="https://speedsync.pl/static/img/banner.png">
  </picture>
</p>

<p align="center">
  ⏱️ SpeedSync is an advanced Assetto Corsa telemetry plugin that tracks lap times, sector times, and theoretical best performance with seamless cloud integration.
</p>

---

## Racing telemetry shouldn't be complicated

Whether you're a casual sim racer or a competitive driver, tracking your performance is essential. SpeedSync makes it effortless to collect, analyze, and improve your lap times with real-time sector tracking and cloud synchronization.

The plugin runs directly within Assetto Corsa, capturing detailed telemetry data including lap times, sector splits, and theoretical best times. All data is automatically synchronized with the SpeedSync API at [speedsync.pl](https://speedsync.pl), allowing you to track your progress across sessions and compare performance.

## Features

**⏱️ Real-time Sector Tracking**  
Automatic detection and recording of sector times. Track both session-best and all-time best sector times.

**🏆 Theoretical Best Calculation**  
Automatically calculates your theoretical best lap time by combining your best sector times, showing you exactly how much time you can gain.

**☁️ Cloud Synchronization**  
All lap data is automatically saved to the SpeedSync API, allowing you to access your telemetry from anywhere and track long-term progress.

**👤 User Authentication**  
Secure login system with optional "Remember Me" functionality. Each driver's data is stored separately for accurate leaderboards and statistics.

**🔄 Session Management**  
Intelligent session detection that tracks your progress within each session while maintaining historical all-time records.

**📊 Smart Data Collection**  
Uses Assetto Corsa's shared memory interface for accurate, low-latency data collection without impacting game performance.

## Installation

SpeedSync is designed to work seamlessly with Assetto Corsa's plugin system.

### Installing the plugin

1. Download the latest release
2. Extract the `SpeedSync` folder to your Assetto Corsa apps directory
3. Launch Assetto Corsa and enable the plugin from the apps menu

### First-time setup

1. Click on the SpeedSync app icon in Assetto Corsa
2. Register a new account or log in with your existing credentials
3. Start driving - lap data will be automatically tracked and synchronized!

### Requirements

- Assetto Corsa (64-bit or 32-bit)
- Internet connection for cloud synchronization
- Python 3.x libraries (included in `stdlib` and `stdlib64`)

## How to Use

### Getting Started

Once installed and authenticated, SpeedSync runs automatically in the background. Simply start any session (Practice, Qualifying, or Race) and the plugin will begin tracking your performance.

### Understanding the Interface

The SpeedSync app displays real-time information:

- **Current Lap Time** - Your ongoing lap time
- **Last Lap Time** - Time from your previous completed lap
- **Best Lap Time** - Your fastest lap in the current session
- **Sector Times** - Individual sector splits (S1, S2, S3)
- **Theoretical Best** - The fastest possible lap combining your best sectors
- **Delta** - Time difference compared to your best lap

### Viewing Your Stats

All your telemetry data is synchronized to your SpeedSync account at [speedsync.pl](https://speedsync.pl), where you can:

- View detailed lap history and analysis
- Compare performance across different sessions and tracks
- Track your improvement over time
- Analyze sector-by-sector performance
- See leaderboards and compare with other drivers

### Tips for Best Results

- **Complete clean laps** - Invalid laps (cutting corners, going off-track) won't count toward your best times
- **Focus on consistency** - The theoretical best shows where you can improve by combining your best sectors
- **Track progression** - Monitor your improvement session-by-session through the web interface
- **Stay connected** - Ensure stable internet connection for automatic cloud sync

## How it works

SpeedSync integrates with Assetto Corsa through the `ac` and `acsys` APIs, while also accessing shared memory for enhanced telemetry:

- **`AppState`** - Manages global application state including session tracking and authentication
- **`SectorTracker`** - Handles real-time sector detection and theoretical best calculation  
- **`LapDataManager`** - Manages lap data persistence and API synchronization
- **`APIClient`** - Handles all communication with the SpeedSync backend
- **`AuthManager`** - Manages user authentication and session persistence

All data is processed in a background worker thread (`lap_worker`) to ensure zero impact on game performance.

## Architecture

The plugin uses a modular architecture with separate concerns:

- **Core telemetry**: Direct integration with Assetto Corsa APIs
- **Shared memory**: Access to `SPageFilePhysics` and `SPageFileGraphic` for enhanced data
- **Background processing**: Threaded worker system using Python's `queue` module
- **Cloud sync**: RESTful API client with automatic retry and error handling

## API Integration

SpeedSync communicates with the backend API:

- User authentication and registration
- Lap data persistence
- Best sector times retrieval
- Historical performance tracking

All API requests include authentication via API keys stored securely in the `API_CONFIG`.

## Contributing

Contributions are welcome! Whether you want to add new features, fix bugs, or improve documentation, please feel free to submit a pull request.

## License

SpeedSync is open source software. See the license file for more information.

## Support

For questions, bug reports, or feature requests, please visit [speedsync.pl](https://speedsync.pl) or contact the development team.

---

**Made with ❤️ for the sim racing community**

Happy racing! 🏁
