import { useState, useEffect } from "react";
import { add, multiply, test } from "./utils";
import Calculator from "./components/Calculator";
import InfoAboutApp from "./components/InfoAboutApp";
import './App.css';

function App() {
  const [count, setCount] = useState(0);

  return (
    <div className="App">
      <InfoAboutApp />
      <div id="wrapper">
        <div id="calculator-wrapper">
          <Calculator />
        </div>
      </div>
    </div>
  );
}

export default App;
