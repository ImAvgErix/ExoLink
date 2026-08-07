export type EmojiEntry = readonly [emoji: string, name: string];
export type EmojiCategory = readonly [category: string, entries: readonly EmojiEntry[]];

/** A local, dependency-free emoji catalogue for the composer picker. */
export const EMOJI_CATALOG: readonly EmojiCategory[] = [
  ["Smileys", [
    ["😀", "grinning"], ["😃", "smile"], ["😄", "happy"], ["😁", "beam"],
    ["😆", "laugh"], ["😅", "sweat smile"], ["😂", "tears joy"], ["🤣", "rolling laugh"],
    ["😊", "blush"], ["😇", "angel"], ["🙂", "slight smile"], ["🙃", "upside down"],
    ["😉", "wink"], ["😌", "relieved"], ["😍", "heart eyes"], ["🥰", "love hearts"],
    ["😘", "kiss"], ["😋", "yum"], ["😎", "cool"], ["🤓", "nerd"],
    ["🧐", "monocle"], ["🤩", "star eyes"], ["🥳", "party"], ["😏", "smirk"],
    ["😒", "unamused"], ["😔", "sad"], ["😢", "cry"], ["😭", "sob"],
    ["😤", "triumph"], ["😡", "angry"], ["🤬", "swear"], ["🤯", "mind blown"],
    ["😱", "scream"], ["😳", "flushed"], ["🥺", "pleading"], ["🤔", "thinking"],
    ["🫡", "salute"], ["🤫", "quiet"], ["🫠", "melting"], ["💀", "skull"],
    ["😴", "sleeping"], ["🤗", "hug"], ["🤭", "hand over mouth"], ["🤥", "lying"],
    ["😬", "grimace"], ["🙄", "roll eyes"], ["😮‍💨", "exhale"], ["😵‍💫", "dizzy face"],
    ["🥶", "cold"], ["🥵", "hot"], ["🤠", "cowboy"], ["🥸", "disguise"],
    ["🤡", "clown"], ["👻", "ghost"], ["👽", "alien"], ["🤖", "robot"],
  ]],
  ["People", [
    ["👋", "wave"], ["🤚", "raised back hand"], ["🖐️", "hand"], ["✋", "raised hand"],
    ["🫱", "right hand"], ["🫲", "left hand"], ["🫶", "heart hands"], ["🤝", "handshake"],
    ["👍", "thumbs up"], ["👎", "thumbs down"], ["👏", "clap"], ["🙌", "raise hands"],
    ["🙏", "please thanks"], ["💪", "strong"], ["👌", "okay"], ["✌️", "peace"],
    ["🤞", "fingers crossed"], ["🤟", "love you"], ["🤘", "rock"], ["🤙", "call me"],
    ["👀", "eyes"], ["🫵", "you"], ["👂", "ear"], ["👃", "nose"],
    ["🧠", "brain"], ["🫀", "anatomical heart"], ["🦷", "tooth"], ["🦴", "bone"],
    ["👶", "baby"], ["🧒", "child"], ["🧑", "person"], ["👩", "woman"],
    ["👨", "man"], ["🧓", "older person"], ["🧑‍💻", "developer"], ["🧑‍🎨", "artist"],
  ]],
  ["Hearts", [
    ["❤️", "red heart"], ["🩷", "pink heart"], ["🧡", "orange heart"], ["💛", "yellow heart"],
    ["💚", "green heart"], ["💙", "blue heart"], ["💜", "purple heart"], ["🖤", "black heart"],
    ["🤍", "white heart"], ["🤎", "brown heart"], ["🩵", "light blue heart"], ["🩶", "grey heart"],
    ["💔", "broken heart"], ["❤️‍🔥", "heart fire"], ["❤️‍🩹", "mending heart"], ["💕", "two hearts"],
    ["💞", "revolving hearts"], ["💓", "beating heart"], ["💗", "growing heart"], ["💖", "sparkling heart"],
    ["💘", "heart arrow"], ["💝", "heart ribbon"], ["❣️", "exclamation heart"], ["💟", "heart decoration"],
    ["💯", "hundred"], ["💥", "boom"], ["✨", "sparkles"], ["🔥", "fire"],
  ]],
  ["Animals", [
    ["🐶", "dog"], ["🐱", "cat"], ["🐭", "mouse"], ["🐹", "hamster"],
    ["🐰", "rabbit"], ["🦊", "fox"], ["🐻", "bear"], ["🐼", "panda"],
    ["🐨", "koala"], ["🐯", "tiger"], ["🦁", "lion"], ["🐮", "cow"],
    ["🐷", "pig"], ["🐸", "frog"], ["🐵", "monkey"], ["🙈", "see no evil"],
    ["🐔", "chicken"], ["🐧", "penguin"], ["🐦", "bird"], ["🦄", "unicorn"],
    ["🐝", "bee"], ["🦋", "butterfly"], ["🐌", "snail"], ["🐞", "lady beetle"],
    ["🐢", "turtle"], ["🐍", "snake"], ["🦎", "lizard"], ["🐙", "octopus"],
    ["🦀", "crab"], ["🐠", "tropical fish"], ["🐳", "whale"], ["🦖", "dinosaur"],
  ]],
  ["Food", [
    ["🍏", "green apple"], ["🍎", "red apple"], ["🍐", "pear"], ["🍊", "orange"],
    ["🍋", "lemon"], ["🍌", "banana"], ["🍉", "watermelon"], ["🍇", "grapes"],
    ["🍓", "strawberry"], ["🫐", "blueberries"], ["🍒", "cherries"], ["🍑", "peach"],
    ["🥝", "kiwi"], ["🍕", "pizza"], ["🍔", "burger"], ["🍟", "fries"],
    ["🌭", "hot dog"], ["🌮", "taco"], ["🌯", "burrito"], ["🍣", "sushi"],
    ["🍿", "popcorn"], ["🍩", "donut"], ["🍪", "cookie"], ["🎂", "birthday cake"],
    ["🍫", "chocolate"], ["🍭", "lollipop"], ["☕", "coffee"], ["🧋", "bubble tea"],
    ["🍺", "beer"], ["🍻", "cheers"], ["🍷", "wine"], ["🥂", "champagne"],
  ]],
  ["Things", [
    ["🎉", "celebrate"], ["🎁", "gift"], ["🎮", "game"], ["🎧", "headphones"],
    ["🎵", "music"], ["🎸", "guitar"], ["📸", "camera"], ["💡", "idea"],
    ["✅", "check"], ["❌", "cross"], ["⚠️", "warning"], ["🚀", "rocket"],
    ["⭐", "star"], ["🌙", "moon"], ["☀️", "sun"], ["⚡", "lightning"],
    ["💎", "diamond"], ["🏆", "trophy"], ["🎯", "target"], ["🎨", "art"],
    ["📚", "books"], ["📝", "memo"], ["📌", "pin"], ["🔒", "lock"],
    ["🔑", "key"], ["🔔", "bell"], ["📱", "phone"], ["💻", "laptop"],
    ["🖥️", "desktop"], ["⌚", "watch"], ["💸", "money"], ["🎈", "balloon"],
  ]],
  ["Travel & Nature", [
    ["🌍", "earth"], ["🌎", "earth americas"], ["🌏", "earth asia"], ["🌈", "rainbow"],
    ["☁️", "cloud"], ["🌧️", "rain"], ["❄️", "snow"], ["🌸", "cherry blossom"],
    ["🌻", "sunflower"], ["🌲", "evergreen"], ["🌵", "cactus"], ["🍀", "four leaf clover"],
    ["🏖️", "beach"], ["⛰️", "mountain"], ["🏕️", "camping"], ["✈️", "airplane"],
    ["🚗", "car"], ["🚲", "bicycle"], ["🚂", "train"], ["🚢", "ship"],
    ["🗺️", "map"], ["🧭", "compass"], ["🏠", "house"], ["🏙️", "city"],
  ]],
  ["Symbols", [
    ["➕", "plus"], ["➖", "minus"], ["✖️", "multiply"], ["➗", "divide"],
    ["‼️", "double exclamation"], ["⁉️", "question exclamation"], ["❓", "question"], ["❗", "exclamation"],
    ["⭕", "circle"], ["🚫", "prohibited"], ["💤", "zzz"], ["♻️", "recycle"],
    ["☑️", "ballot check"], ["✔️", "check mark"], ["🔴", "red circle"], ["🟢", "green circle"],
    ["🔵", "blue circle"], ["🟣", "purple circle"], ["⚪", "white circle"], ["⚫", "black circle"],
  ]],
] as const;

export function searchEmojiCatalog(query: string): readonly EmojiCategory[] {
  const normalized = query.trim().toLocaleLowerCase();
  if (!normalized) return EMOJI_CATALOG;
  return EMOJI_CATALOG.flatMap(([category, entries]) => {
    const visible = entries.filter(
      ([emoji, name]) =>
        name.toLocaleLowerCase().includes(normalized) || emoji.includes(normalized),
    );
    return visible.length > 0 ? ([[category, visible] as const]) : [];
  });
}

